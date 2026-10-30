import Foundation

/// Transport-independent events. Strings from helper / extension are decoded at the adapter boundary.
public enum VPNDiagnosticCode: Equatable, Sendable {
    public enum Lifecycle: String, Sendable {
        case starting, connecting, connected, server_unreachable, disconnected
        case network_changed, invalid_profile, busy, cleanup_error, error, closed
        case heartbeat_timeout, client_closed, control_error, helper_lost
        case validation_failed, authorization_failed, launch_failed, start_failed
        case system_sleep, system_wake, health_check_requested
        case recovery_ready, recovery_failed, recovery_expired, recovery_exhausted
        case cancelled, stop_requested, previous_session_incomplete, reasserting
    }
    public enum Health: String, Sendable { case checking, ok, dns, route, degraded, unavailable
        case network_unavailable, source_unconfirmed, name_unavailable, egress_unconfirmed, tunnel_unreachable }
    public enum Stage: String, Sendable {
        case resolve, physical, tunnel, engine, endpoint_route, transport, routes, dns, cleanup
    }
    public enum Probe: String, Sendable {
        case route, tcp, tls, fallback_tcp, fallback_tls, system_dns, direct_dns, complete
        case fallback_name, outside_tls, outside_fallback_tls, handshake_fresh, rx_progress, tx_progress
    }
    public enum Outcome: String, Sendable { case ok, failed, timeout, dns_failed }
    case configurationUpdate(ManagedConfigurationRecovery.Outcome)
    case recoveryAttempt(UInt64)
    case checkStarted(UUID)
    case lifecycle(Lifecycle)
    case health(Health)
    case stage(Stage, succeeded: Bool, milliseconds: UInt64, errno: UInt64)
    case probe(Probe, Outcome)
    case counters(handshake: Bool, sent: UInt64, received: UInt64)
    case flow(read: UInt64, written: UInt64, unknownIP: UInt64, errors: UInt64, sendErrors: UInt64, errno: UInt64)

    public init?(wireValue: String) {
        guard wireValue.utf8.count <= 256 else { return nil }
        if let value = Lifecycle(rawValue: wireValue) { self = .lifecycle(value); return }
        let pair = wireValue.split(separator: "=", omittingEmptySubsequences: false)
        guard pair.count == 2 else { return nil }
        let key = String(pair[0]), value = String(pair[1])
        if key == "configuration_update", let outcome = ManagedConfigurationRecovery.Outcome(rawValue: value) {
            self = .configurationUpdate(outcome); return
        }
        if key == "recovery_attempt", let attempt = UInt64(value), (1...3).contains(attempt), value == String(attempt) {
            self = .recoveryAttempt(attempt); return
        }
        if key == "check_started", let id = UUID(uuidString: value) { self = .checkStarted(id); return }
        if key == "health", let health = Health(rawValue: value) { self = .health(health); return }
        if key.hasPrefix("probe_"), let probe = Probe(rawValue: String(key.dropFirst(6))),
           let outcome = Outcome(rawValue: value) { self = .probe(probe, outcome); return }
        let fields = value.split(separator: ",", omittingEmptySubsequences: false)
        func number(_ value: Substring) -> UInt64? {
            guard !value.isEmpty, value.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
            return UInt64(value)
        }
        if key.hasPrefix("step_"), let stage = Stage(rawValue: String(key.dropFirst(5))), fields.count == 3,
           ["ok", "failed"].contains(String(fields[0])), let ms = number(fields[1]), let errno = number(fields[2]) {
            self = .stage(stage, succeeded: fields[0] == "ok", milliseconds: ms, errno: errno); return
        }
        let numbers = fields.compactMap(number)
        guard numbers.count == fields.count else { return nil }
        if key == "stats", numbers.count == 3, numbers[0] <= 1 {
            self = .counters(handshake: numbers[0] == 1, sent: numbers[1], received: numbers[2]); return
        }
        if key == "flow", numbers.count == 6 {
            self = .flow(read: numbers[0], written: numbers[1], unknownIP: numbers[2], errors: numbers[3], sendErrors: numbers[4], errno: numbers[5]); return
        }
        return nil
    }

    public var wireValue: String {
        switch self {
        case .configurationUpdate(let outcome): return "configuration_update=\(outcome.rawValue)"
        case .recoveryAttempt(let attempt): return "recovery_attempt=\(attempt)"
        case .checkStarted(let id): return "check_started=\(id.uuidString)"
        case .lifecycle(let value): return value.rawValue
        case .health(let value): return "health=\(value.rawValue)"
        case .stage(let stage, let succeeded, let ms, let errno):
            return "step_\(stage.rawValue)=\(succeeded ? "ok" : "failed"),\(ms),\(errno)"
        case .probe(let probe, let outcome): return "probe_\(probe.rawValue)=\(outcome.rawValue)"
        case .counters(let handshake, let sent, let received): return "stats=\(handshake ? 1 : 0),\(sent),\(received)"
        case .flow(let read, let written, let unknownIP, let errors, let sendErrors, let errno):
            return "flow=\(read),\(written),\(unknownIP),\(errors),\(sendErrors),\(errno)"
        }
    }
}

public struct VPNDiagnosticEvent: Sendable {
    public enum Kind: Sendable { case began, code(VPNDiagnosticCode), ended }
    public let sessionID: UUID
    public let kind: Kind
    public let time: Date
    public init(sessionID: UUID, kind: Kind, at time: Date = Date()) {
        self.sessionID = sessionID; self.kind = kind; self.time = time
    }
}

/// One emitter per adapter. Async callbacks must retain the ID of their own attempt.
@MainActor
public final class VPNDiagnosticEmitter {
    public var onEvent: ((VPNDiagnosticEvent) -> Void)?
    public private(set) var sessionID: UUID?
    public init() {}
    @discardableResult public func begin() -> UUID {
        let id = UUID()
        sessionID = id
        onEvent?(VPNDiagnosticEvent(sessionID: id, kind: .began))
        return id
    }
    public func record(_ code: VPNDiagnosticCode, sessionID id: UUID) {
        guard sessionID == id else { return }
        onEvent?(VPNDiagnosticEvent(sessionID: id, kind: .code(code)))
    }
    public func end(sessionID id: UUID) {
        guard sessionID == id else { return }
        onEvent?(VPNDiagnosticEvent(sessionID: id, kind: .ended))
        sessionID = nil
    }
}
