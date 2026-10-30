import Foundation
import XCTest
@testable import UndercoreMacCore

final class ConnectionDiagnosticReportTests: XCTestCase {
    func testRejectsSecretsAndArbitraryOutput() throws {
        var report = ConnectionDiagnosticReport()
        for value in ["private_key=SECRET", "endpoint=PRIVATE", "stats=1,2,SECRET", "stats=1,2,3\nSECRET",
                      "stats=2,3,4", "stats=1,-1,2", "stats=1,18446744073709551616,0", "probe_tls=SECRET", "connected\nSECRET",
                      "flow=1,2,3,4,5,SECRET", "flow=1,2,3,4,5,-1", "step_engine=failed,1,SECRET", "step_PRIVATE=ok,1,0", "health=SECRET"] {
            XCTAssertFalse(report.record(value), value)
        }
        XCTAssertTrue(report.events.isEmpty)
        for value in ["starting", "stats=1,456,789", "probe_tcp=ok", "probe_system_dns=timeout", "flow=1,2,3,4,5,51", "step_routes=failed,15,51", "health=dns", "closed"] {
            XCTAssertTrue(report.record(value), value)
        }
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(report), as: UTF8.self).contains("SECRET"))
        XCTAssertEqual(report.events.count, 8)
    }
    func testReportRemainsBoundedAndRetainsFailure() {
        var report = ConnectionDiagnosticReport()
        report.record("starting"); report.record("step_routes=failed,3,51")
        for i in 0..<1000 { report.record("stats=1,\(i),789") }
        XCTAssertEqual(report.events.count, 256)
        XCTAssertEqual(report.events.first?.value, "starting")
        XCTAssertTrue(report.events.contains { $0.value == "step_routes=failed,3,51" })
        XCTAssertEqual(report.events.last?.value, "stats=1,999,789")
    }
    func testRepeatedFailuresAreAggregated() {
        var report = ConnectionDiagnosticReport()
        for _ in 0..<200 { report.record("health=degraded") }
        XCTAssertEqual(report.events.count, 1)
        XCTAssertEqual(report.events.first?.repetitions, 200)
    }
    func testHealthSurvivesLateHandshakeAndRecovers() {
        var health = ConnectionHealth()
        XCTAssertEqual(health.state, .checking)
        XCTAssertTrue(health.receive("health=ok")); XCTAssertEqual(health.state, .connected)
        XCTAssertFalse(health.receive("connected")); XCTAssertEqual(health.state, .connected)
        XCTAssertTrue(health.receive("health=degraded")); XCTAssertEqual(health.state, .degraded)
        XCTAssertFalse(health.receive("connected")); XCTAssertEqual(health.state, .degraded)
        XCTAssertTrue(health.receive("health=ok")); XCTAssertEqual(health.state, .connected)
    }
}
