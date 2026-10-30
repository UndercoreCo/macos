#if USE_NETWORK_EXTENSION
import Combine
import NetworkExtension
import UndercoreMacCore

@MainActor
final class NetworkExtensionBackend: VPNBackend {
    static let providerID = "ru.undercore.macos.tunnel"
    var onRecoveryEvent: ((VPNRecoveryEvent) -> Void)?
    var onStateChange: ((VPNState, String?) -> Void)?
    private let diagnostics = VPNDiagnosticEmitter()
    var onDiagnosticEvent: ((VPNDiagnosticEvent) -> Void)? {
        get { diagnostics.onEvent }
        set { diagnostics.onEvent = newValue }
    }
    private var reconnectConfiguration: Data?
    private var retrying = false
    private var preparing = false
    private(set) var requiresSystemExtensionApproval = false
    private var updatingConfiguration = false
    private var lastStatus: NEVPNStatus?
    private let activation = ExtensionActivation()
    private var manager: NETunnelProviderManager?
    private var observer: AnyCancellable?
    private var operation = UUID()
    private var runID: UUID?
    private var poller: Task<Void, Never>?
    private var pollGeneration = UUID()
    private var gate = HealthCheckGate()
    private var health = ConnectionHealth()
    private var lastHealthEvidence: (UUID, VPNDiagnosticCode.Health)?
    var canCancelPending: Bool { preparing }
    var supportsConfigurationUpdates: Bool { true }
    var canReconnect: Bool { reconnectConfiguration != nil && manager?.isEnabled == true }

    func validate(configuration: Data) async throws { try validateTransport(configuration) }

    private func validateTransport(_ data: Data) throws {
        let transport = try VPNTransportConfiguration.parse(data)
        #if !TRUSTTUNNEL_EXPERIMENTAL
        if case .trustTunnel = transport { throw ClientError.unsupportedConfiguration }
        #endif
    }

    func reconnect() throws {
        guard let data = reconnectConfiguration, let manager, manager.isEnabled,
              manager.connection.status == .disconnected,
              let session = manager.connection as? NETunnelProviderSession else { throw VPNRecoveryError.unavailable }
        retrying = true
        health = ConnectionHealth(); gate = HealthCheckGate()
        try start(session, data: data)
        lastStatus = .connecting
        onStateChange?(.reasserting, "Восстанавливаем соединение…")
    }

    func prepareForConfigurationRefresh() async throws {
        _ = try await pausedRecoverySession()
    }

    func reconnect(configuration: Data?) async throws {
        guard let data = configuration ?? reconnectConfiguration else { throw VPNRecoveryError.unavailable }
        try validateTransport(data)
        let session = try await pausedRecoverySession()
        try Task.checkCancellation()
        guard canReconnect, session.status == .disconnected else { throw VPNRecoveryError.unavailable }
        health = ConnectionHealth(); gate = HealthCheckGate()
        retrying = true
        try start(session, data: data)
        reconnectConfiguration = data
        lastStatus = .connecting
    }

    private func pausedRecoverySession() async throws -> NETunnelProviderSession {
        guard canReconnect, let manager, let session = manager.connection as? NETunnelProviderSession else {
            throw VPNRecoveryError.unavailable
        }
        try Task.checkCancellation()
        let token = operation
        updatingConfiguration = true
        defer { updatingConfiguration = false }
        stopPolling()
        onStateChange?(.reasserting, "Восстанавливаем соединение…")
        if session.status != .disconnected {
            session.stopVPNTunnel()
            for _ in 0..<50 {
                try requireCurrent(token)
                try Task.checkCancellation()
                if session.status == .disconnected { break }
                try await Task.sleep(for: .milliseconds(100))
            }
        }
        try requireCurrent(token)
        try Task.checkCancellation()
        guard session.status == .disconnected, manager.isEnabled, reconnectConfiguration != nil else {
            throw VPNRecoveryError.unavailable
        }
        return session
    }

    func restore() async throws {
        if let manager = try await ownedManager() { observe(manager) }
        else { onStateChange?(.disconnected, nil) }
    }

    func connect(configuration data: Data, profile: ConnectionProfile) async throws {
        try validateTransport(data)
        operation = UUID(); let token = operation
        let attempt = diagnostics.begin()
        preparing = true; lastStatus = nil
        requiresSystemExtensionApproval = false
        health = ConnectionHealth(); gate = HealthCheckGate()
        onStateChange?(.connecting, "")
        var started = false
        defer {
            if operation == token {
                preparing = false
                requiresSystemExtensionApproval = false
                if !started {
                    diagnostics.record(.lifecycle(.start_failed), sessionID: attempt)
                    diagnostics.end(sessionID: attempt)
                    onStateChange?(.disconnected, nil)
                }
            }
        }
        activation.awaitingApproval = { [weak self] in
            guard let self, self.operation == token else { return }
            self.requiresSystemExtensionApproval = true
            self.onStateChange?(.connecting, "Требуется разрешение macOS")
        }
        try await activation.activate()
        try requireCurrent(token)
        requiresSystemExtensionApproval = false
        onStateChange?(.connecting, "")
        let manager = try await ownedManager() ?? NETunnelProviderManager()
        try requireCurrent(token)
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = Self.providerID
        configuration.serverAddress = "Undercore"
        configuration.providerConfiguration = ["profileID": profile.id.uuidString]
        configuration.disconnectOnSleep = false
        manager.protocolConfiguration = configuration
        manager.localizedDescription = "Undercore"
        manager.isEnabled = true
        manager.isOnDemandEnabled = false
        try await manager.saveToPreferences()
        try requireCurrent(token)
        try await manager.loadFromPreferences()
        try requireCurrent(token)
        observe(manager)
        guard let session = manager.connection as? NETunnelProviderSession else { throw Failure.start }
        try start(session, data: data)
        reconnectConfiguration = data
        retrying = false; started = true; preparing = false
        if [.connected, .connecting, .reasserting].contains(manager.connection.status) {
            emit(manager.connection.status)
        } else {
            lastStatus = .connecting
            diagnostics.record(.lifecycle(.connecting), sessionID: attempt)
            onStateChange?(.connecting, "")
        }
    }

    private func requireCurrent(_ token: UUID) throws {
        guard operation == token else { throw CancellationError() }
    }
    private func start(_ session: NETunnelProviderSession, data: Data) throws {
        stopPolling(); runID = UUID()
        try session.startTunnel(options: ["configuration": data as NSData, "runID": runID!.uuidString as NSString])
    }

    func disconnect() async {
        operation = UUID(); preparing = false
        requiresSystemExtensionApproval = false
        activation.cancel()
        reconnectConfiguration = nil; retrying = false
        stopPolling(); gate = HealthCheckGate()
        onRecoveryEvent?(.unavailable)
        if let id = diagnostics.sessionID { diagnostics.record(.lifecycle(.stop_requested), sessionID: id) }
        manager?.connection.stopVPNTunnel()
        emit(manager?.connection.status ?? .disconnected)
    }
    func remove() async throws {
        reconnectConfiguration = nil; stopPolling()
        if let manager { try await manager.removeFromPreferences() }
        observer = nil; manager = nil
    }

    func handleSystemEvent(_ event: VPNSystemEvent) {
        guard !preparing else { return }
        guard let id = diagnostics.sessionID else { return }
        switch event {
        case .willSleep:
            gate.willSleep(); stopPolling()
            diagnostics.record(.lifecycle(.system_sleep), sessionID: id)
            onStateChange?(.checking, "После пробуждения проверим соединение")
        case .didWake:
            diagnostics.record(.lifecycle(.system_wake), sessionID: id)
            requestHealthCheck()
        }
    }
    func requestHealthCheck() {
        guard !preparing else { return }
        guard let id = diagnostics.sessionID else { return }
        stopPolling(); _ = gate.request(); health = ConnectionHealth()
        diagnostics.record(.lifecycle(.health_check_requested), sessionID: id)
        onStateChange?(.checking, health.message)
        if manager?.connection.status == .connected { startPolling() }
    }

    private func ownedManager() async throws -> NETunnelProviderManager? {
        let all = try await NETunnelProviderManager.loadAllFromPreferences().filter {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.providerID
        }
        guard all.count <= 1 else { throw Failure.preferences }
        return all.first
    }
    private func observe(_ manager: NETunnelProviderManager) {
        self.manager = manager
        emit(manager.connection.status)
        observer = NotificationCenter.default.publisher(for: .NEVPNStatusDidChange, object: manager.connection)
            .receive(on: RunLoop.main).sink { [weak self, weak manager] _ in
                guard let self, let manager, self.manager === manager else { return }
                self.emit(manager.connection.status)
            }
    }
    private func emit(_ status: NEVPNStatus) {
        guard !preparing, !updatingConfiguration else { return }
        let unexpectedlyStopped = status == .disconnected && canReconnect
        let active = [.connecting, .connected, .reasserting, .disconnecting].contains(status) || unexpectedlyStopped
        if active && diagnostics.sessionID == nil { diagnostics.begin() }
        let changed = status != lastStatus
        lastStatus = status
        let state: VPNState
        let code: VPNDiagnosticCode.Lifecycle
        switch status {
        case .connected:
            state = health.state; code = .connected
            if !gate.sleeping { startPolling() }
        case .connecting: state = .connecting; code = .connecting
        case .reasserting: state = .reasserting; code = .reasserting
        case .disconnecting: state = .disconnecting; code = .stop_requested
        default: state = .disconnected; code = .disconnected
        }
        if status != .connected { stopPolling(); health = ConnectionHealth() }
        if changed, let id = diagnostics.sessionID { diagnostics.record(.lifecycle(code), sessionID: id) }
        if !active, let id = diagnostics.sessionID {
            onRecoveryEvent?(.unavailable); diagnostics.end(sessionID: id)
        }
        if unexpectedlyStopped && changed { onRecoveryEvent?(retrying ? .attemptFailed : .required) }
        onStateChange?(unexpectedlyStopped ? .reasserting : state, status == .connected ? health.message : "")
    }

    private func stopPolling() {
        pollGeneration = UUID(); poller?.cancel(); poller = nil
    }
    private func startPolling() {
        guard poller == nil else { return }
        let token = pollGeneration
        let fastPollingUntil = ProcessInfo.processInfo.systemUptime + 15
        poller = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, self.pollGeneration == token else { return }
                await self.poll(token: token)
                // Read the local extension promptly during startup. This does not
                // launch network probes or increase calls to the account API.
                let awaitingFirstResult = self.health.state == .checking
                    && ProcessInfo.processInfo.systemUptime < fastPollingUntil
                do { try await Task.sleep(for: .milliseconds(awaitingFirstResult ? 300 : 3000)) }
                catch { return }
            }
        }
    }
    private func poll(token: UUID) async {
        guard let session = manager?.connection as? NETunnelProviderSession,
              session.status == .connected, let attempt = diagnostics.sessionID else { return }
        let pending = gate.pending
        let request = TunnelStatusRequest(command: pending == nil ? .status : .check, id: pending ?? UUID())
        let data = await message(request, session: session)
        guard pollGeneration == token, diagnostics.sessionID == attempt, !gate.sleeping,
              manager?.connection === session, session.status == .connected else { return }
        guard let data, let reply = TunnelStatusReply.decode(data, requestID: request.id, runID: runID) else {
            _ = health.receive(.health(.unavailable))
            diagnostics.record(.health(.unavailable), sessionID: attempt)
            onRecoveryEvent?(.inconclusive)
            onStateChange?(health.state, health.message)
            return
        }
        runID = reply.runID
        if let pending {
            guard reply.checkID == pending else { return }
            gate.acknowledge(pending)
            diagnostics.record(.checkStarted(pending), sessionID: attempt)
        }
        guard gate.acceptsResults else { return }
        var freshHealth = false
        for raw in reply.codes {
            guard let code = VPNDiagnosticCode(wireValue: raw) else { continue }
            if case .health(let value) = code {
                if lastHealthEvidence?.0 != reply.checkID || lastHealthEvidence?.1 != value {
                    diagnostics.record(code, sessionID: attempt)
                    lastHealthEvidence = (reply.checkID, value)
                    freshHealth = true
                }
            } else { diagnostics.record(code, sessionID: attempt) }
            _ = health.receive(code)
        }
        if health.result == .ok { retrying = false; onRecoveryEvent?(.restored) }
        if freshHealth {
            switch health.result {
            case .tunnel_unreachable: onRecoveryEvent?(retrying ? .attemptFailed : .required)
            case .checking: onRecoveryEvent?(.checking)
            case .ok: break
            default: onRecoveryEvent?(.inconclusive)
            }
        }
        onStateChange?(health.state, health.message)
    }
    private func message(_ request: TunnelStatusRequest, session: NETunnelProviderSession) async -> Data? {
        guard let data = try? JSONEncoder().encode(request) else { return nil }
        return await withCheckedContinuation { continuation in
            var finished = false
            let finish: (Data?) -> Void = { value in
                guard !finished else { return }; finished = true
                continuation.resume(returning: value)
            }
            do {
                try session.sendProviderMessage(data) { value in Task { @MainActor in finish(value) } }
            } catch { finish(nil) }
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(5))
                finish(nil)
            }
        }
    }
}
#endif
