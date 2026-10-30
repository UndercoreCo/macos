import Foundation

/// A result queued before sleep must not validate connectivity after wake.
public struct HealthCheckGate: Sendable {
    public private(set) var pending: UUID?
    public private(set) var sleeping = false
    public init() {}
    public var acceptsResults: Bool { !sleeping && pending == nil }
    public mutating func willSleep() { sleeping = true; pending = nil }
    public mutating func request() -> UUID {
        sleeping = false
        let id = UUID(); pending = id
        return id
    }
    public mutating func acknowledge(_ id: UUID) {
        if !sleeping && pending == id { pending = nil }
    }
}
