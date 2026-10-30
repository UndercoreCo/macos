import Foundation
import XCTest
@testable import UndercoreMacCore

final class HealthCheckGateTests: XCTestCase {
    func testSleepAndWakeRejectOldHealthUntilMatchingAcknowledgment() {
        var gate = HealthCheckGate()
        XCTAssertTrue(gate.acceptsResults)
        gate.willSleep()
        XCTAssertFalse(gate.acceptsResults)
        let old = gate.request()
        let current = gate.request()
        gate.acknowledge(old)
        XCTAssertFalse(gate.acceptsResults)
        gate.acknowledge(current)
        XCTAssertTrue(gate.acceptsResults)
        gate.willSleep()
        gate.acknowledge(current)
        XCTAssertFalse(gate.acceptsResults)
    }
    func testPostWakeSuccessfulProbeIsNotHiddenByDeduplication() {
        var recorder = DiagnosticSessionRecorder()
        let id = UUID(), now = Date()
        _ = recorder.receive(.init(sessionID: id, kind: .began, at: now))
        let probe = VPNDiagnosticCode.probe(.tls, .ok)
        _ = recorder.receive(.init(sessionID: id, kind: .code(probe), at: now))
        XCTAssertTrue(recorder.receive(.init(sessionID: id, kind: .code(probe), at: now.addingTimeInterval(10))).isEmpty)
        _ = recorder.receive(.init(sessionID: id, kind: .code(.lifecycle(.system_wake)), at: now.addingTimeInterval(20)))
        XCTAssertEqual(recorder.receive(.init(sessionID: id, kind: .code(probe), at: now.addingTimeInterval(21))).count, 1)
        XCTAssertEqual(recorder.report?.events.filter { $0.value == "probe_tls=ok" }.count, 2)
    }
    func testHealthCheckAcknowledgmentAcceptsOnlyUUID() {
        let id = UUID()
        XCTAssertEqual(VPNDiagnosticCode(wireValue: "check_started=" + id.uuidString), .checkStarted(id))
        XCTAssertNil(VPNDiagnosticCode(wireValue: "check_started=private-key"))
    }
}
