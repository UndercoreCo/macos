import XCTest
@testable import UndercoreMacCore

final class UpdateInstallationGateTests: XCTestCase {
    @MainActor func testActiveVPNDefersUntilExplicitSafeRetryAndRunsOnlyOnce() {
        let gate = UpdateInstallationGate()
        var installed = 0
        XCTAssertTrue(gate.postpone(if: true) { installed += 1 })
        gate.resume(ifSafe: false)
        XCTAssertEqual(installed, 0)
        XCTAssertTrue(gate.hasPending)
        gate.resume(ifSafe: true)
        gate.resume(ifSafe: true)
        XCTAssertEqual(installed, 1)
        XCTAssertFalse(gate.hasPending)
    }

    @MainActor func testAbortedUpdateCannotInstallLater() {
        let gate = UpdateInstallationGate()
        var installed = false
        _ = gate.postpone(if: true) { installed = true }
        gate.cancel()
        gate.resume(ifSafe: true)
        XCTAssertFalse(installed)
    }

    @MainActor func testIdleLetsSparkleContinueWithoutCallingItsHandlerTwice() {
        let gate = UpdateInstallationGate()
        XCTAssertFalse(gate.postpone(if: false) { XCTFail("Sparkle owns immediate installation") })
        XCTAssertFalse(gate.hasPending)
    }
}
