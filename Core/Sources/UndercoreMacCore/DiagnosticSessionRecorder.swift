import Foundation

/// Common session rules; no OSLog, disk, helper protocol or NetworkExtension dependency.
/// Confined by its owner to one serial queue.
public struct DiagnosticSessionRecorder {
    public private(set) var report: ConnectionDiagnosticReport?
    private var lastSamples: [String: Date] = [:]
    private var lastProbes: [String: (String, Date)] = [:]
    public init() {}

    /// Returns only changed reports to persist, including an interrupted predecessor.
    public mutating func receive(_ event: VPNDiagnosticEvent,
                                 context: ConnectionDiagnosticReport.Context = .init()) -> [ConnectionDiagnosticReport] {
        switch event.kind {
        case .began:
            guard report?.id != event.sessionID else { return [] }
            var changed: [ConnectionDiagnosticReport] = []
            if var old = report, !old.isFinished {
                old.record("previous_session_incomplete", at: event.time); changed.append(old)
            }
            report = ConnectionDiagnosticReport(context: context, at: event.time, id: event.sessionID)
            lastSamples = [:]; lastProbes = [:]
            report?.record("starting", at: event.time)
            if let report { changed.append(report) }
            return changed
        case .code(let code):
            guard report?.id == event.sessionID, report?.isFinished == false else { return [] }
            // Lifecycle boundaries belong to .began/.ended, not backend payloads.
            guard code != .lifecycle(.starting), code != .lifecycle(.closed),
                  code != .lifecycle(.previous_session_incomplete) else { return [] }
            if code == .lifecycle(.system_wake) || code == .lifecycle(.health_check_requested) {
                lastProbes = [:]
            }
            if case .recoveryAttempt = code { lastProbes = [:]; lastSamples = [:] }
            return record(code.wireValue, at: event.time)
        case .ended:
            guard report?.id == event.sessionID, report?.isFinished == false else { return [] }
            return record("closed", at: event.time)
        }
    }
    private mutating func record(_ line: String, at date: Date) -> [ConnectionDiagnosticReport] {
        let key = String(line.split(separator: "=").first ?? "")
        if ConnectionDiagnosticReport.isSample(line) {
            guard date.timeIntervalSince(lastSamples[key] ?? .distantPast) >= 14 else { return [] }
            lastSamples[key] = date
        }
        if key.hasPrefix("probe_") {
            if let previous = lastProbes[key], previous.0 == line, date.timeIntervalSince(previous.1) < 300 { return [] }
            lastProbes[key] = (line, date)
        }
        guard report?.record(line, at: date) == true, let report else { return [] }
        return [report]
    }
}
