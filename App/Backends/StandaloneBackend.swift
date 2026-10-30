#if !USE_NETWORK_EXTENSION
import AppKit
import CryptoKit
import UndercoreMacCore

@MainActor
final class StandaloneBackend: VPNBackend {
    var canCancelPending: Bool { true }
    var onRecoveryEvent: ((VPNRecoveryEvent) -> Void)?
    var canReconnect: Bool { connection != nil && !stopping }

    func reconnect() throws {
        guard let connection, !stopping else { throw VPNRecoveryError.unavailable }
        terminalMessage = nil
        health = ConnectionHealth()
        let request = healthGate.request()
        onStateChange?(.reasserting, "Восстанавливаем соединение…")
        do { try connection.send(Data("reconnect \(request.uuidString)\n".utf8)) }
        catch { connection.close(); throw VPNRecoveryError.unavailable }
    }
    var onStateChange: ((VPNState, String?) -> Void)?
    private var authorization: Process?
    private var connection: HelperConnection?
    private var heartbeat: Task<Void, Never>?
    private var receiver: Task<Void, Never>?
    private var stopping = false
    private var terminalMessage: String?
    private let diagnostics = VPNDiagnosticEmitter()
    var onDiagnosticEvent: ((VPNDiagnosticEvent) -> Void)? {
        get { diagnostics.onEvent }
        set { diagnostics.onEvent = newValue }
    }
    private var healthGate = HealthCheckGate()
    private var health = ConnectionHealth()

    func restore() async throws { onStateChange?(.disconnected, nil) }
    func remove() async throws { guard connection == nil else { throw Failure.start } }

    func validate(configuration: Data) async throws {
        _ = try ProfileConfiguration.parse(configuration)
        guard let helper = Bundle.main.url(forResource: "undercore-helper", withExtension: nil) else { throw Failure.start }
        let valid = try await Task.detached {
            let validator = Process()
            validator.executableURL = helper
            validator.arguments = ["--check"]
            let input = Pipe()
            validator.standardInput = input
            validator.standardOutput = FileHandle.nullDevice
            validator.standardError = FileHandle.nullDevice
            try validator.run()
            defer {
                try? input.fileHandleForWriting.close()
                if validator.isRunning { validator.terminate() }
                validator.waitUntilExit()
            }
            try input.fileHandleForWriting.write(contentsOf: configuration)
            try input.fileHandleForWriting.close()
            validator.waitUntilExit()
            return validator.terminationStatus == 0
        }.value
        guard valid else { throw ProfileError.unsupportedStandaloneProfile }
    }

    func connect(configuration: Data, profile: ConnectionProfile) async throws {
        guard authorization == nil else { throw Failure.start }
        let sessionID = diagnostics.begin()
        var didStart = false
        defer { if !didStart { diagnostics.end(sessionID: sessionID) } }
        healthGate = HealthCheckGate()
        health = ConnectionHealth()
        do { try await validate(configuration: configuration) }
        catch { record("validation_failed", sessionID: sessionID); throw error }
        guard let helper = Bundle.main.url(forResource: "undercore-helper", withExtension: nil) else { throw Failure.start }
        terminalMessage = nil
        stopping = false
        let hash = SHA256.hash(data: try Data(contentsOf: helper)).map { String(format: "%02x", $0) }.joined()
        let session = UUID().uuidString.lowercased()
        let directory = "/private/var/run/undercore-\(session)"
        let socket = directory + "/control.sock"
        // Only installation paths and a binary digest enter the shell. Never config values.
        let command = """
        set -eu
        umask 077
        /bin/mkdir -m 711 \(quote(directory))
        trap '/bin/rm -f \(directory)/helper \(socket); /bin/rmdir \(directory)' EXIT
        /usr/bin/install -o root -g wheel -m 700 \(quote(helper.path)) \(quote(directory + "/helper"))
        actual=$(/usr/bin/shasum -a 256 \(quote(directory + "/helper")))
        test "${actual%% *}" = \(quote(hash))
        /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \(quote(directory + "/helper")) --uid \(getuid()) --pid \(getpid()) --socket \(quote(socket))
        """
        let script = "with timeout of 31536000 seconds\ndo shell script " + appleScriptString(command) + " with administrator privileges\nend timeout\n"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-"]
        let input = Pipe()
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() }
        catch { record("launch_failed", sessionID: sessionID); throw error }
        authorization = process
        do {
            try input.fileHandleForWriting.write(contentsOf: Data(script.utf8))
            try input.fileHandleForWriting.close()
            onStateChange?(.connecting, "Разрешите подключение в системном окне macOS")
            var stream: HelperConnection?
            for _ in 0..<600 {
                if !process.isRunning { record("authorization_failed", sessionID: sessionID); throw Failure.start }
                if let connected = try? HelperConnection(path: socket) { stream = connected; break }
                try await Task.sleep(for: .milliseconds(200))
            }
            guard let stream else { throw Failure.start }
            connection = stream
            stopping = false
            let payload = try JSONEncoder().encode(Request(configuration: configuration)) + Data([10])
            try stream.send(payload)
            heartbeat = Task { [weak self] in
                while !Task.isCancelled {
                    do {
                        try await Task.sleep(for: .seconds(5))
                        try stream.send(Data("ping\n".utf8))
                    } catch { break }
                }
                self?.heartbeat = nil
            }
            didStart = true
            receiver = Task.detached { [weak self] in
                do {
                    while let line = try stream.receiveLine() { await self?.received(line, sessionID: sessionID) }
                } catch {}
                await self?.finished(sessionID: sessionID)
            }
        } catch {
            record(stopping ? "cancelled" : "start_failed", sessionID: sessionID)
            connection?.close(); connection = nil
            if process.isRunning { process.terminate() }
            authorization = nil
            onStateChange?(.disconnected, nil)
            if stopping { throw CancellationError() }
            throw Failure.start
        }
    }

    func disconnect() async {
        stopping = true
        if let sessionID = diagnostics.sessionID { record("stop_requested", sessionID: sessionID) }
        if connection == nil, let authorization, authorization.isRunning { authorization.terminate() }
        onRecoveryEvent?(.unavailable)
        onStateChange?(.disconnecting, nil)
        do { try connection?.send(Data("stop\n".utf8)) }
        catch { connection?.close() } // EOF also asks the helper to clean up.
    }

    func handleSystemEvent(_ event: VPNSystemEvent) {
        guard connection != nil, !stopping, let id = diagnostics.sessionID else { return }
        switch event {
        case .willSleep:
            diagnostics.record(.lifecycle(.system_sleep), sessionID: id)
            healthGate.willSleep()
            _ = health.receive(.health(.checking))
            onStateChange?(.checking, "После пробуждения проверим доступ к интернету")
        case .didWake:
            diagnostics.record(.lifecycle(.system_wake), sessionID: id)
            requestHealthCheck()
        }
    }

    func requestHealthCheck() {
        guard let connection, !stopping, let id = diagnostics.sessionID else { return }
        let request = healthGate.request()
        _ = health.receive(.health(.checking))
        diagnostics.record(.lifecycle(.health_check_requested), sessionID: id)
        diagnostics.record(.health(.checking), sessionID: id)
        onStateChange?(health.state, health.message)
        do { try connection.send(Data("check \(request.uuidString)\n".utf8)) }
        catch { connection.close() } // Existing EOF path reports disconnect and cleans up.
    }

    private func received(_ line: String, sessionID: UUID) {
        guard diagnostics.sessionID == sessionID else { return }
        guard let code = VPNDiagnosticCode(wireValue: line) else { return }
        if case .checkStarted(let request) = code { healthGate.acknowledge(request) }
        if case .health = code, !healthGate.acceptsResults { return }
        if case .probe = code, !healthGate.acceptsResults { return }
        diagnostics.record(code, sessionID: sessionID)
        // A late probe can be queued while the user is disconnecting.
        if health.receive(code) {
            if !stopping {
                if health.result == .ok { onRecoveryEvent?(.restored) }
                else if [.dns, .route, .degraded].contains(health.result) { onRecoveryEvent?(.required) }
                onStateChange?(health.state, health.message)
            }
            return
        }
        if case .stage(let stage, false, _, _) = code {
            terminalMessage = "Не удалось выполнить этап настройки VPN: " + stepTitle(stage) + "."
        }
        guard case .lifecycle(let lifecycle) = code else { return }
        switch lifecycle {
        case .connecting: if stopping { return }; onStateChange?(.connecting, "Ожидаем ответ VPN-сервера…")
        case .connected: if !stopping { onStateChange?(health.state, health.message) }
        case .server_unreachable:
            if stopping { return }
            if health.result != nil { onStateChange?(health.state, health.message) }
            else { onStateChange?(.connecting, "Сервер VPN пока не отвечает. Можно отключиться и попробовать снова.") }
        case .disconnected: stopping = true
        case .network_changed: break // Recovery begins only after the old tunnel has been cleaned up.
        case .recovery_ready, .recovery_failed:
            guard !stopping else { return }
            health = ConnectionHealth()
            healthGate = HealthCheckGate()
            onRecoveryEvent?(lifecycle == .recovery_failed ? .attemptFailed : .required)
            onStateChange?(.reasserting, "Восстанавливаем соединение…")
        case .recovery_expired:
            terminalMessage = "Не удалось восстановить VPN. Подключитесь ещё раз."
            onRecoveryEvent?(.unavailable)
        case .invalid_profile: terminalMessage = "Этот файл не поддерживается текущим VPN-компонентом."
        case .busy: terminalMessage = "Другое подключение Undercore уже запущено."
        case .cleanup_error: terminalMessage = "Не удалось полностью завершить очистку сети. Проверьте подключение к интернету."
        case .error: if terminalMessage == nil { terminalMessage = "Не удалось настроить VPN." }
        default: break
        }
    }

    private func stepTitle(_ stage: VPNDiagnosticCode.Stage) -> String {
        switch stage {
        case .resolve: return "поиск сервера"
        case .physical: return "проверка сети"
        case .tunnel: return "создание туннеля"
        case .engine: return "запуск VPN"
        case .endpoint_route: return "маршрут к серверу"
        case .transport: return "связь с сервером"
        case .routes: return "маршруты"
        case .dns: return "DNS"
        case .cleanup: return "восстановление сети"
        }
    }

    private func finished(sessionID: UUID) {
        guard diagnostics.sessionID == sessionID else { return }
        if !stopping && terminalMessage == nil { record("helper_lost", sessionID: sessionID) }
        onRecoveryEvent?(.unavailable)
        diagnostics.end(sessionID: sessionID)
        heartbeat?.cancel(); heartbeat = nil
        connection?.close(); connection = nil
        authorization = nil
        receiver = nil
        onStateChange?(.disconnected, terminalMessage ?? (stopping ? nil : "Подключение завершено. Попробуйте подключиться снова."))
    }

    private func record(_ wireValue: String, sessionID: UUID) {
        guard let code = VPNDiagnosticCode(wireValue: wireValue) else { return }
        diagnostics.record(code, sessionID: sessionID)
    }

    private struct Request: Encodable { let configuration: Data }
    private func quote(_ text: String) -> String { "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    private func appleScriptString(_ text: String) -> String {
        "\"" + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}
#endif
