import Foundation

public enum VPNSystemEvent: Sendable { case willSleep, didWake }

/// UI and account logic never depend on a particular VPN transport implementation.
@MainActor
public protocol VPNBackend: AnyObject {
    var onDiagnosticEvent: ((VPNDiagnosticEvent) -> Void)? { get set }
    var canCancelPending: Bool { get }
    /// True only while a system extension activation is waiting for user approval.
    var requiresSystemExtensionApproval: Bool { get }
    var onRecoveryEvent: ((VPNRecoveryEvent) -> Void)? { get set }
    var canReconnect: Bool { get }
    /// Reuse existing authorization only. Never prompt, provision, or launch a privileged process.
    func reconnect() throws
    var supportsConfigurationUpdates: Bool { get }
    /// Pause the failed tunnel and restore physical routing before contacting the account API.
    func prepareForConfigurationRefresh() async throws
    /// Restart an already authorized tunnel. Must never activate extensions or request credentials.
    func reconnect(configuration: Data?) async throws
    var onStateChange: ((VPNState, String?) -> Void)? { get set }
    func validate(configuration: Data) async throws
    func handleSystemEvent(_ event: VPNSystemEvent)
    func requestHealthCheck()
    func restore() async throws
    func connect(configuration: Data, profile: ConnectionProfile) async throws
    func disconnect() async
    func remove() async throws
}

public extension VPNBackend {
    var canCancelPending: Bool { false }
    var requiresSystemExtensionApproval: Bool { false }
    var canReconnect: Bool { false }
    var supportsConfigurationUpdates: Bool { false }
    func prepareForConfigurationRefresh() async throws { throw VPNRecoveryError.unavailable }
    func reconnect(configuration: Data?) async throws {
        guard configuration == nil else { throw VPNRecoveryError.unavailable }
        try reconnect()
    }
    func reconnect() throws { throw VPNRecoveryError.unavailable }
    func validate(configuration: Data) async throws {
        _ = try ProfileConfiguration.parse(configuration)
    }
}
