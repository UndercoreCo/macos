import Foundation

/// Authenticated export kept only in memory, never encoded into preferences or diagnostics.
public struct ManagedConfiguration: Sendable {
    public let data: Data
    public enum RevisionScope: Equatable, Sendable {
        case legacy
        case connection(deviceID: String, connectionID: String)
    }
    public let revision: Int
    public let revisionScope: RevisionScope
    public let expiresAt: Date?
    public let automaticRecoveryAllowed: Bool

    public init(data: Data, revisionHeader: String?) throws {
        guard let raw = revisionHeader, let revision = Int(raw), raw == String(revision),
              (1...2_147_483_647).contains(revision) else { throw ClientError.invalidResponse }
        try self.init(data: data, revision: revision, revisionScope: .legacy, expiresAt: nil)
    }

    init(data: Data, revision: Int, revisionScope: RevisionScope, expiresAt: Date?, automaticRecoveryAllowed: Bool = false) throws {
        guard (1...2_147_483_647).contains(revision) else { throw ClientError.invalidResponse }
        _ = try VPNTransportConfiguration.parse(data)
        self.data = data
        self.revision = revision
        self.revisionScope = revisionScope
        self.expiresAt = expiresAt
        self.automaticRecoveryAllowed = automaticRecoveryAllowed
    }
}

/// A small, bounded update budget for one explicitly started VPN session.
@MainActor
public final class ManagedConfigurationRecovery {
    public enum Outcome: String, Sendable { case checking, requestingAlternative, unchanged, available, applied, unavailable, rejected, accessDenied }
    public var onOutcome: ((Outcome) -> Void)?
    public private(set) var current: ManagedConfiguration
    private var pending: ManagedConfiguration?
    private var fetching = false
    private var checks = 0
    private var recoveryRevision: Int?
    private var recoveryCalls = 0
    private var recoveryCompleted = false
    private var nextRecoveryCheck: TimeInterval = 0
    private var nextCheck: TimeInterval = 0
    private let now: () -> TimeInterval
    private let timeout: Duration
    private let recoveryTimeout: Duration
    private let sleep: @MainActor @Sendable (Duration) async throws -> Void

    public init(current: ManagedConfiguration, timeout: Duration = .seconds(20),
                recoveryTimeout: Duration = .seconds(330),
                sleep: @escaping @MainActor @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) },
                now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) {
        self.current = current
        self.timeout = timeout
        self.recoveryTimeout = recoveryTimeout
        self.sleep = sleep
        self.now = now
    }

    public func refresh(attempt: Int = 1, allowAlternative: Bool = false,
                        recover: (@MainActor @Sendable (Int) async throws -> ManagedConfiguration)? = nil,
                        fetch: @escaping @MainActor @Sendable () async throws -> ManagedConfiguration) async throws -> Data? {
        guard !fetching else { return nil }
        if let pending { return pending.data }
        let useAlternative = allowAlternative && attempt >= 2 && current.automaticRecoveryAllowed
            && current.revisionScope != .legacy && recover != nil && !recoveryCompleted
        let operation: @MainActor @Sendable () async throws -> ManagedConfiguration
        if useAlternative, let recover {
            guard recoveryCalls < 2, now() >= nextRecoveryCheck else { return nil }
            let revision = recoveryRevision ?? current.revision
            recoveryRevision = revision // Freeze before sending: ambiguous responses retry this operation only.
            recoveryCalls += 1
            let sleep = self.sleep
            operation = {
                // Repeat the same revision only when the server explicitly reports pending revocation.
                // Generic 503s are never retried here. The outer timeout also bounds slow HTTP calls.
                for poll in 0...11 {
                    try Task.checkCancellation()
                    do { return try await recover(revision) }
                    catch ClientError.recoveryPending(let retry) {
                        guard poll < 11 else { throw ClientError.recoveryPending(retryAfter: retry) }
                        try await sleep(.seconds(min(max(retry, 5), 60)))
                    }
                }
                throw ClientError.invalidResponse
            }
            onOutcome?(.requestingAlternative)
        } else {
            guard checks < 2, now() >= nextCheck else { return nil }
            checks += 1
            nextCheck = now() + 60
            operation = fetch
            onOutcome?(.checking)
        }
        fetching = true
        defer { fetching = false }
        do {
            let timeout = useAlternative ? self.recoveryTimeout : self.timeout
            let candidate = try await withThrowingTaskGroup(of: ManagedConfiguration.self) { group in
                group.addTask { try await operation() }
                group.addTask {
                    try await Task.sleep(for: timeout)
                    throw URLError(.timedOut)
                }
                defer { group.cancelAll() }
                return try await group.next()!
            }
            try Task.checkCancellation()
            // Revision counters belong to one contract and connection. A cutover requires a new explicit connect.
            guard candidate.revisionScope == current.revisionScope,
                  candidate.revision >= current.revision,
                  candidate.revisionScope == .legacy || candidate.revision != current.revision
                    || (candidate.data == current.data && candidate.expiresAt == current.expiresAt) else {
                onOutcome?(.rejected)
                return nil
            }
            if useAlternative { recoveryCompleted = true }
            guard candidate.data != current.data else {
                current = candidate
                onOutcome?(.unchanged)
                return nil
            }
            // Key replacement may legitimately change the export within the same node revision.
            pending = candidate
            onOutcome?(.available)
            return candidate.data
        } catch is CancellationError { throw CancellationError() }
        catch {
            try Task.checkCancellation()
            if let error = error as? ClientError {
                switch error {
                case .expiredSession, .wrongAccount, .unverified, .unavailable, .insecureStorage,
                     .server(status: 401, retryAfter: _), .server(status: 403, retryAfter: _),
                     .server(status: 404, retryAfter: _), .server(status: 410, retryAfter: _):
                    onOutcome?(.accessDenied)
                    throw error
                case .server(status: 429, retryAfter: let retry):
                    nextCheck = max(nextCheck, now() + TimeInterval(retry ?? 60))
                    nextRecoveryCheck = max(nextRecoveryCheck, now() + TimeInterval(retry ?? 60))
                default: break
                }
            }
            onOutcome?(.unavailable)
            return nil // A transient API failure must not erase the last accepted configuration.
        }
    }

    public func didReconnect() {
        guard let pending else { return }
        current = pending
        self.pending = nil
        onOutcome?(.applied)
    }
}
