import Foundation

/// Bounded, versioned IPC. Raw engine UAPI must never leave the extension.
public struct TunnelStatusRequest: Codable, Sendable {
    public enum Command: String, Codable, Sendable { case status, check }
    public let version: Int
    public let id: UUID
    public let command: Command
    public init(command: Command, id: UUID = UUID()) { version = 1; self.id = id; self.command = command }
    public static func decode(_ data: Data) -> Self? {
        guard data.count <= 512, let value = try? JSONDecoder().decode(Self.self, from: data), value.version == 1 else { return nil }
        return value
    }
}

public struct TunnelStatusReply: Codable, Sendable {
    public let version: Int
    public let requestID: UUID
    public let runID: UUID
    public let checkID: UUID
    public let codes: [String]
    public init(requestID: UUID, runID: UUID, checkID: UUID, codes: [VPNDiagnosticCode]) {
        version = 1; self.requestID = requestID; self.runID = runID; self.checkID = checkID
        self.codes = codes.map(\.wireValue)
    }
    public static func decode(_ data: Data, requestID: UUID, runID: UUID?) -> Self? {
        guard data.count <= 4096, let value = try? JSONDecoder().decode(Self.self, from: data),
              value.version == 1, value.requestID == requestID,
              runID == nil || value.runID == runID, value.codes.count <= 12,
              value.codes.filter({ $0.hasPrefix("health=") }).count == 1,
              value.codes.allSatisfy({ raw in
                  guard let code = VPNDiagnosticCode(wireValue: raw) else { return false }
                  switch code { case .health, .probe, .counters: return true; default: return false }
              }) else { return nil }
        return value
    }
}

public struct TunnelCounters: Equatable, Sendable {
    public let lastHandshake: UInt64
    public var handshake: Bool { lastHandshake > 0 }
    public func hasFreshHandshake(at now: TimeInterval) -> Bool {
        lastHandshake > 0 && Double(lastHandshake) <= now && now - Double(lastHandshake) <= 180
    }
    public let sent: UInt64
    public let received: UInt64
    public static func parse(_ text: String) -> Self? {
        guard text.utf8.count <= 65536 else { return nil }
        var values: [String: UInt64] = [:]
        for line in text.split(separator: "\n") {
            let pair = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pair.count == 2, ["last_handshake_time_sec", "tx_bytes", "rx_bytes"].contains(String(pair[0])) else { continue }
            guard values[String(pair[0])] == nil, !pair[1].isEmpty,
                  pair[1].allSatisfy({ $0.isASCII && $0.isNumber }), let number = UInt64(pair[1]) else { return nil }
            values[String(pair[0])] = number
        }
        guard let time = values["last_handshake_time_sec"], let sent = values["tx_bytes"], let received = values["rx_bytes"] else { return nil }
        return Self(lastHandshake: time, sent: sent, received: received)
    }
    public var diagnostic: VPNDiagnosticCode { .counters(handshake: handshake, sent: sent, received: received) }
}

