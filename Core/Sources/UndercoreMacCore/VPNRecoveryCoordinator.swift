import Foundation

/// Retry timing and user intent belong above the interchangeable transport adapter.
@MainActor
public final class VPNRecoveryCoordinator {
    public var onChange: ((String?) -> Void)?
    public var onExhausted: (() -> Void)?
    public var configurationForRecovery: (() async throws -> Data?)?
    public var onPreparationFailure: ((Error) -> Void)?
    public var onReconnectSucceeded: (() -> Void)?
    public var onDiagnosticEvent: ((VPNDiagnosticEvent) -> Void)?
    public var networkAvailable = false {
        didSet { if !networkAvailable { failureEvidenceAt = nil } }
    }
    private var failureEvidenceAt: TimeInterval?
    public var canRequestAlternative: Bool {
        guard networkAvailable, let failureEvidenceAt else { return false }
        return now() >= failureEvidenceAt && now() - failureEvidenceAt <= 120
    }
    public func networkChanged() { failureEvidenceAt = nil }
    public var attempt: Int { policy.attempts }
    public var recovering: Bool { policy.recovering }
    private var policy = VPNRecoveryPolicy()
    private let backend: any VPNBackend
    private var timer: Task<Void, Never>?
    private var pendingReconnect: Task<Void, Never>?
    private var generation = UUID()
    private var sessionID: UUID?
    private let now: () -> TimeInterval
    public init(backend: any VPNBackend, now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.backend = backend
        self.now = now
    }
    public func observe(_ event: VPNDiagnosticEvent) {
        switch event.kind {
        case .began: sessionID = event.sessionID; failureEvidenceAt = nil
        case .ended:
            if sessionID == event.sessionID { sessionID = nil; failureEvidenceAt = nil }
        case .code(let code):
            guard event.sessionID == sessionID else { return }
            if case .health(let health) = code {
                switch health {
                case .tunnel_unreachable: failureEvidenceAt = now()
                case .checking, .unavailable: break
                default: failureEvidenceAt = nil
                }
            }
            if code == .lifecycle(.network_changed) { failureEvidenceAt = nil }
        }
    }
    private func record(_ code: VPNDiagnosticCode) {
        guard let sessionID else { return }
        onDiagnosticEvent?(VPNDiagnosticEvent(sessionID: sessionID, kind: .code(code)))
    }
    deinit { timer?.cancel(); pendingReconnect?.cancel() }

    public func start() {
        cancel()
        policy.start()
    }
    private func startTimer() {
        guard timer == nil else { return }
        let generation = self.generation
        timer = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(1)) } catch { return }
                guard let self, self.generation == generation else { return }
                self.tick()
            }
        }
    }
    private func stopTimer() {
        generation = UUID()
        timer?.cancel(); timer = nil
        pendingReconnect?.cancel(); pendingReconnect = nil
    }
    public func cancel() { stopTimer(); policy.cancel(); failureEvidenceAt = nil }
    public func setSleeping(_ sleeping: Bool) {
        policy.setSleeping(sleeping, at: now())
        if sleeping { failureEvidenceAt = nil; stopTimer() }
        else if policy.recovering { startTimer() }
    }
    public func receive(_ event: VPNRecoveryEvent) {
        policy.receive(event, at: now())
        if policy.recovering { startTimer() } else { stopTimer() }
        publish()
    }
    private func publish() {
        onChange?(policy.recovering
            ? (networkAvailable ? "Восстанавливаем VPN. Попыток: \(policy.attempts) из 3" : "Ждём возвращения сети, затем восстановим VPN")
            : nil)
    }
    func tick() {
        guard pendingReconnect == nil else { return }
        switch policy.tick(at: now(), networkAvailable: networkAvailable, canReconnect: backend.canReconnect) {
        case .none:
            if policy.recovering { publish() }
        case .retry:
            record(.recoveryAttempt(UInt64(policy.attempts)))
            publish()
            // This entry point MUST NOT request authorization or launch a new privileged process.
            if let prepare = configurationForRecovery {
                reconnectAfterPreparation(prepare)
            } else {
                do { try backend.reconnect() }
                catch { receive(.attemptFailed) }
            }
        case .stop:
            record(.lifecycle(.recovery_exhausted))
            cancel()
            onExhausted?()
        }
    }
    private func reconnectAfterPreparation(_ prepare: @escaping () async throws -> Data?) {
        let token = generation
        pendingReconnect = Task { [weak self] in
            guard let self else { return }
            defer { if self.generation == token { self.pendingReconnect = nil } }
            do { try await self.backend.prepareForConfigurationRefresh() }
            catch {
                guard self.generation == token, !Task.isCancelled else { return }
                self.receive(.attemptFailed)
                return
            }
            guard self.generation == token, !Task.isCancelled else { return }
            let configuration: Data?
            do { configuration = try await prepare() }
            catch {
                guard self.generation == token, !Task.isCancelled else { return }
                self.cancel()
                self.onPreparationFailure?(error)
                return
            }
            guard self.generation == token, !Task.isCancelled else { return }
            guard self.networkAvailable, !self.policy.sleeping else {
                self.receive(.attemptFailed)
                return
            }
            self.policy.preparationCompleted(at: self.now())
            do {
                try await self.backend.reconnect(configuration: configuration)
                guard self.generation == token, !Task.isCancelled else { return }
                self.onReconnectSucceeded?()
            } catch {
                guard self.generation == token, !Task.isCancelled else { return }
                self.receive(.attemptFailed)
            }
        }
    }

}
