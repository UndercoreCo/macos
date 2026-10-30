import Foundation

/// Native transport observation, not a claim that a destination is reachable.
public enum TunnelTransportEvidence: Sendable { case unknown, upstreamConnected, upstreamUnavailable }

/// Evidence from one completed check, never from repeated UI/IPC polling.
public struct TunnelHealthObservation: Sendable {
    public let transportEvidence: TunnelTransportEvidence
    public let tunnelIP: Bool
    public let tunnelName: Bool
    public let dnsFailed: Bool
    public let directInternet: Bool
    public let networkAvailable: Bool?
    public let before: TunnelCounters?
    public let after: TunnelCounters?
    public let wallTime: TimeInterval
    public let monotonicTime: TimeInterval
    public init(tunnelIP: Bool, tunnelName: Bool, dnsFailed: Bool = false,
                directInternet: Bool, networkAvailable: Bool? = nil,
                before: TunnelCounters?, after: TunnelCounters?,
                wallTime: TimeInterval, monotonicTime: TimeInterval,
                transportEvidence: TunnelTransportEvidence = .unknown) {
        self.transportEvidence = transportEvidence
        self.tunnelIP = tunnelIP; self.tunnelName = tunnelName; self.dnsFailed = dnsFailed
        self.directInternet = directInternet; self.networkAvailable = networkAvailable
        self.before = before; self.after = after
        self.wallTime = wallTime; self.monotonicTime = monotonicTime
    }
    public var countersComparable: Bool {
        guard let before, let after else { return false }
        return after.sent >= before.sent && after.received >= before.received
    }
    public var receivedResponse: Bool {
        countersComparable && after!.received > before!.received
    }
    public var freshHandshake: Bool { after?.hasFreshHandshake(at: wallTime) == true }
}

/// Recovery needs positive outside-tunnel evidence and repeated missing responses.
public struct TunnelHealthPolicy: Sendable {
    public private(set) var failures = 0
    private var firstFailure: TimeInterval?
    private var lastObservation: TimeInterval?
    public private(set) var result: VPNDiagnosticCode.Health = .checking
    public init() {}
    public mutating func observe(_ o: TunnelHealthObservation) -> VPNDiagnosticCode.Health {
        guard lastObservation == nil || o.monotonicTime > lastObservation! else { return result }
        if let lastObservation, o.monotonicTime - lastObservation > 60 { clearFailures() }
        lastObservation = o.monotonicTime
        if o.tunnelName {
            clearFailures(); result = .ok
        } else if o.tunnelIP {
            clearFailures(); result = o.dnsFailed ? .dns : .name_unavailable
        } else if !o.directInternet {
            clearFailures(); result = o.networkAvailable == false ? .network_unavailable : .source_unconfirmed
        } else if o.transportEvidence == .upstreamUnavailable {
            recordFailure(at: o.monotonicTime)
        } else if o.transportEvidence == .upstreamConnected {
            clearFailures(); result = .egress_unconfirmed
        } else if !o.countersComparable || Double(o.after?.lastHandshake ?? 0) > o.wallTime {
            clearFailures(); result = .degraded
        } else if o.freshHandshake || o.receivedResponse {
            clearFailures(); result = .egress_unconfirmed
        } else {
            recordFailure(at: o.monotonicTime)
        }
        return result
    }
    private mutating func recordFailure(at time: TimeInterval) {
        firstFailure = firstFailure ?? time
        failures += 1
        result = failures >= 3 && time - firstFailure! >= 30 ? .tunnel_unreachable : .checking
    }
    private mutating func clearFailures() { failures = 0; firstFailure = nil }
}
