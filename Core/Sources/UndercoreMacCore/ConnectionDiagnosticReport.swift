import Foundation

/// Only allowlisted codes and numeric counters are persisted or exported.
public struct ConnectionDiagnosticReport: Codable, Sendable {
    public struct Event: Codable, Sendable {
        public let time: Date
        public let value: String
        public var repetitions: Int = 1
        public var lastTime: Date
    }
    public struct Context: Codable, Sendable {
        public let appVersion: String
        public let build: String
        public let systemVersion: String
        public let architecture: String
        public init(appVersion: String = "0", build: String = "0", systemVersion: String = "0", architecture: String = "unknown") {
            func version(_ value: String) -> String {
                value.count <= 32 && !value.isEmpty && value.allSatisfy { $0.isASCII && ($0.isNumber || $0 == ".") } ? value : "0"
            }
            self.appVersion = version(appVersion); self.build = version(build)
            self.systemVersion = version(systemVersion)
            self.architecture = ["arm64", "x86_64"].contains(architecture) ? architecture : "unknown"
        }
        var sanitized: Context { Context(appVersion: appVersion, build: build, systemVersion: systemVersion, architecture: architecture) }
    }
    public let version: Int
    public let id: UUID
    public let startedAt: Date
    public let context: Context
    public private(set) var events: [Event] = []
    public init(context: Context = Context(), at date: Date = Date(), id: UUID = UUID()) {
        version = 2; self.id = id; startedAt = date; self.context = context
    }
    public var isFinished: Bool { events.contains { ["closed", "previous_session_incomplete"].contains($0.value) } }
    public var lastDate: Date { events.last?.lastTime ?? startedAt }

    @discardableResult
    public mutating func record(_ line: String, at time: Date = Date()) -> Bool {
        guard Self.accepts(line) else { return false }
        if events.last?.value == line {
            events[events.count - 1].repetitions = min(events.last!.repetitions + 1, 1_000_000)
            events[events.count - 1].lastTime = time
            return true
        }
        events.append(Event(time: time, value: line, lastTime: time))
        if events.count > 256 {
            // Prefer retaining transitions and failures over periodic samples.
            let index = events.indices.dropFirst().first { Self.isSample(events[$0].value) } ?? 1
            events.remove(at: index)
        }
        return true
    }
    public static func isSample(_ line: String) -> Bool { line.hasPrefix("stats=") || line.hasPrefix("flow=") }
    public static func accepts(_ line: String) -> Bool {
        VPNDiagnosticCode(wireValue: line) != nil
    }
    /// Rebuild decoded files through the whitelist before exporting local data.
    public func sanitized() -> Self {
        var clean = Self(context: context.sanitized, at: startedAt, id: id)
        for event in events.suffix(256) where Self.accepts(event.value) {
            clean.record(event.value, at: event.time)
            let index = clean.events.count - 1
            clean.events[index].repetitions = max(1, min(event.repetitions, 1_000_000))
            clean.events[index].lastTime = event.lastTime
        }
        return clean
    }
}
