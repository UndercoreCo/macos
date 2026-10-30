import Foundation

/// Synchronous disk boundary, called on the app's dedicated serial I/O queue.
public struct DiagnosticArchive {
    public static let sessionLimit = 10
    public static let maximumFileBytes = 128 * 1024
    public static let retention: TimeInterval = 7 * 24 * 60 * 60
    public let directory: URL
    public init(directory: URL) { self.directory = directory }

    public func save(_ report: ConnectionDiagnosticReport, now: Date = Date()) throws {
        let manager = FileManager.default
        try manager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let attributes = try manager.attributesOfItem(atPath: directory.path)
        guard attributes[.type] as? FileAttributeType == .typeDirectory else { throw CocoaError(.fileWriteNoPermission) }
        try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        let data = try encoder().encode(report.sanitized())
        guard data.count <= Self.maximumFileBytes else { throw CocoaError(.fileWriteOutOfSpace) }
        let url = directory.appendingPathComponent(report.id.uuidString + ".json")
        try data.write(to: url, options: .atomic)
        try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        try prune(now: now, keeping: report.id)
    }
    public func reports(now: Date = Date(), keeping: UUID? = nil) throws -> [ConnectionDiagnosticReport] {
        try loaded().map(\.1).filter { $0.id == keeping || now.timeIntervalSince($0.lastDate) <= Self.retention }
            .sorted { $0.startedAt > $1.startedAt }.prefix(Self.sessionLimit).map { $0 }
    }
    public func export(now: Date = Date(), keeping: UUID? = nil) throws -> Data {
        struct Export: Encodable { let version = 1; let sessions: [ConnectionDiagnosticReport] }
        return try encoder().encode(Export(sessions: reports(now: now, keeping: keeping)))
    }
    public func recoverInterrupted(now: Date = Date()) throws {
        for var report in try reports(now: now) where !report.isFinished {
            report.record("previous_session_incomplete", at: now)
            try save(report, now: now)
        }
        try prune(now: now)
    }
    private func encoder() -> JSONEncoder {
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }
    private func loaded(removingInvalid: Bool = false) throws -> [(URL, ConnectionDiagnosticReport)] {
        let manager = FileManager.default
        guard manager.fileExists(atPath: directory.path) else { return [] }
        let directoryAttributes = try manager.attributesOfItem(atPath: directory.path)
        guard directoryAttributes[.type] as? FileAttributeType == .typeDirectory else { throw CocoaError(.fileReadNoPermission) }
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        var records: [(URL, ConnectionDiagnosticReport)] = []
        for url in try manager.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) {
            guard url.pathExtension == "json", UUID(uuidString: url.deletingPathExtension().lastPathComponent) != nil,
                  let attributes = try? manager.attributesOfItem(atPath: url.path),
                  attributes[.type] as? FileAttributeType == .typeRegular else { continue }
            guard let size = attributes[.size] as? NSNumber, size.intValue <= Self.maximumFileBytes,
                  let data = try? Data(contentsOf: url), data.count <= Self.maximumFileBytes,
                  let report = try? decoder.decode(ConnectionDiagnosticReport.self, from: data), report.version == 2,
                  report.id.uuidString == url.deletingPathExtension().lastPathComponent else {
                if removingInvalid { try manager.removeItem(at: url) }
                continue
            }
            records.append((url, report.sanitized()))
        }
        return records
    }
    private func prune(now: Date, keeping: UUID? = nil) throws {
        let records = try loaded(removingInvalid: true).sorted { left, right in
            if left.1.id == keeping { return true }; if right.1.id == keeping { return false }
            return left.1.startedAt > right.1.startedAt
        }
        var retained = 0
        for (url, report) in records {
            if retained < Self.sessionLimit && (report.id == keeping || now.timeIntervalSince(report.lastDate) <= Self.retention) { retained += 1 }
            else { try FileManager.default.removeItem(at: url) }
        }
    }
}
