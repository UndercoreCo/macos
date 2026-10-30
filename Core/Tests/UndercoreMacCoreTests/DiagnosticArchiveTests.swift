import Foundation
import XCTest
@testable import UndercoreMacCore

final class DiagnosticArchiveTests: XCTestCase {
    private func archive() throws -> DiagnosticArchive {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        return DiagnosticArchive(directory: directory)
    }
    func testHistorySurvivesReloadAndRotates() throws {
        let store = try archive(), now = Date()
        for i in 0..<14 {
            let date = now.addingTimeInterval(Double(i))
            var report = ConnectionDiagnosticReport(at: date)
            report.record("starting", at: date); report.record("closed", at: date)
            try store.save(report, now: date)
        }
        let reloaded = DiagnosticArchive(directory: store.directory)
        let reports = try reloaded.reports(now: now.addingTimeInterval(20))
        XCTAssertEqual(reports.count, 10)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: store.directory.path).count, 10)
        XCTAssertEqual(reports.first?.startedAt.timeIntervalSince(now) ?? 0, 13, accuracy: 1)
        XCTAssertLessThan(try store.export(now: now).count, 10 * DiagnosticArchive.maximumFileBytes)
        let attributes = try FileManager.default.attributesOfItem(atPath: store.directory.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
    }
    func testRetentionAndInterruptedRecovery() throws {
        let store = try archive(), old = Date().addingTimeInterval(-8 * 86400), now = Date()
        var expired = ConnectionDiagnosticReport(at: old); expired.record("starting", at: old)
        try store.save(expired, now: old)
        var interrupted = ConnectionDiagnosticReport(at: now); interrupted.record("starting", at: now)
        try store.save(interrupted, now: now)
        try store.recoverInterrupted(now: now)
        let reports = try store.reports(now: now)
        XCTAssertEqual(reports.count, 1)
        XCTAssertTrue(reports[0].isFinished)
        XCTAssertEqual(reports[0].events.last?.value, "previous_session_incomplete")
        try store.recoverInterrupted(now: now)
        XCTAssertEqual(try store.reports(now: now)[0].events.last?.repetitions, 1)
    }
    func testExportSanitizesTamperedFilesAndSkipsSymlinks() throws {
        let store = try archive(), now = Date()
        var report = ConnectionDiagnosticReport(at: now); report.record("starting", at: now)
        try store.save(report, now: now)
        let file = store.directory.appendingPathComponent(report.id.uuidString + ".json")
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        var context = try XCTUnwrap(json["context"] as? [String: Any]); context["appVersion"] = "SECRET"; json["context"] = context
        var events = try XCTUnwrap(json["events"] as? [[String: Any]])
        var event = events[0]; event["value"] = "private_key=SECRET"; events.append(event); json["events"] = events
        json["private_key"] = "SECRET"
        try JSONSerialization.data(withJSONObject: json).write(to: file)
        let link = store.directory.appendingPathComponent(UUID().uuidString + ".json")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        let export = String(decoding: try store.export(now: now), as: UTF8.self)
        XCTAssertFalse(export.contains("SECRET")); XCTAssertFalse(export.contains("private_key"))
        XCTAssertEqual(try store.reports(now: now).count, 1)
    }
    func testRecoveryRemovesCorruptAndOversizedOwnedReportsOnly() throws {
        let store = try archive()
        try FileManager.default.createDirectory(at: store.directory, withIntermediateDirectories: true)
        let corrupt = store.directory.appendingPathComponent(UUID().uuidString + ".json")
        let oversized = store.directory.appendingPathComponent(UUID().uuidString + ".json")
        let unrelated = store.directory.appendingPathComponent("keep.txt")
        try Data("broken".utf8).write(to: corrupt)
        try Data(repeating: 0, count: DiagnosticArchive.maximumFileBytes + 1).write(to: oversized)
        try Data("keep".utf8).write(to: unrelated)
        try store.recoverInterrupted()
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: store.directory.path), ["keep.txt"])
    }

}
