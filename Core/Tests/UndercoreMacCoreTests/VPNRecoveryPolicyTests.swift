import XCTest
@testable import UndercoreMacCore

final class VPNRecoveryPolicyTests: XCTestCase {
    func testOfflineWaitDoesNotSpendAttemptsAndReturnResumes() {
        var policy = VPNRecoveryPolicy()
        policy.start()
        policy.receive(.required, at: 0)
        XCTAssertEqual(policy.tick(at: 30, networkAvailable: false, canReconnect: true), .none)
        XCTAssertEqual(policy.attempts, 0)
        XCTAssertEqual(policy.tick(at: 31, networkAvailable: true, canReconnect: true), .retry)
        XCTAssertEqual(policy.attempts, 1)
        XCTAssertEqual(policy.tick(at: 32, networkAvailable: true, canReconnect: true), .none)
    }
    func testThreeAttemptsWithIncreasingDelayThenStops() {
        var policy = VPNRecoveryPolicy()
        policy.start(); policy.receive(.required, at: 0)
        XCTAssertEqual(policy.tick(at: 1, networkAvailable: true, canReconnect: true), .none)
        XCTAssertEqual(policy.tick(at: 2, networkAvailable: true, canReconnect: true), .retry)
        policy.receive(.attemptFailed, at: 3)
        XCTAssertEqual(policy.tick(at: 7, networkAvailable: true, canReconnect: true), .none)
        XCTAssertEqual(policy.tick(at: 8, networkAvailable: true, canReconnect: true), .retry)
        policy.receive(.attemptFailed, at: 9)
        XCTAssertEqual(policy.tick(at: 23, networkAvailable: true, canReconnect: true), .none)
        XCTAssertEqual(policy.tick(at: 24, networkAvailable: true, canReconnect: true), .retry)
        policy.receive(.attemptFailed, at: 25)
        XCTAssertEqual(policy.tick(at: 26, networkAvailable: true, canReconnect: true), .stop)
        XCTAssertEqual(policy.tick(at: 500, networkAvailable: true, canReconnect: true), .none)
    }
    func testCheckingAllowsEvidenceToCompleteAndUncertaintyStopsDisruptiveRetries() {
        var policy = VPNRecoveryPolicy()
        policy.start(); policy.receive(.required, at: 0)
        XCTAssertEqual(policy.tick(at: 2, networkAvailable: true, canReconnect: true), .retry)
        for time in [25.0, 50.0, 75.0] {
            policy.receive(.checking, at: time)
            XCTAssertEqual(policy.tick(at: time + 1, networkAvailable: true, canReconnect: true), .none)
        }
        XCTAssertEqual(policy.attempts, 1)
        policy.receive(.inconclusive, at: 80)
        XCTAssertFalse(policy.recovering)
        XCTAssertEqual(policy.tick(at: 1000, networkAvailable: true, canReconnect: true), .none)
        XCTAssertEqual(policy.attempts, 1)
        policy.receive(.required, at: 1000)
        XCTAssertEqual(policy.tick(at: 1005, networkAvailable: true, canReconnect: true), .retry)
        XCTAssertEqual(policy.attempts, 2)
    }
    func testCheckingCannotExtendOverallRecoveryDeadline() {
        var policy = VPNRecoveryPolicy()
        policy.start(); policy.receive(.required, at: 0)
        _ = policy.tick(at: 2, networkAvailable: true, canReconnect: true)
        for time in stride(from: 25.0, through: 400.0, by: 25.0) { policy.receive(.checking, at: time) }
        XCTAssertEqual(policy.tick(at: 420, networkAvailable: true, canReconnect: true), .stop)
    }
    func testManualDisconnectCannotBeUndoneByLateNetworkOrHealthEvents() {
        var policy = VPNRecoveryPolicy()
        policy.start(); policy.receive(.required, at: 0)
        policy.cancel()
        for event: VPNRecoveryEvent in [.required, .attemptFailed, .restored] { policy.receive(event, at: 5) }
        XCTAssertEqual(policy.tick(at: 20, networkAvailable: true, canReconnect: true), .none)
        XCTAssertFalse(policy.enabled)
    }
    func testSleepSuppressesRetriesAndHealthyWakePreservesTunnel() {
        var policy = VPNRecoveryPolicy()
        policy.start(); policy.receive(.required, at: 0)
        policy.setSleeping(true, at: 1)
        XCTAssertEqual(policy.tick(at: 10, networkAvailable: true, canReconnect: true), .none)
        policy.setSleeping(false, at: 11)
        policy.receive(.restored, at: 11)
        XCTAssertEqual(policy.tick(at: 12, networkAvailable: true, canReconnect: true), .none)
        XCTAssertFalse(policy.recovering)
    }
    func testOfflineDeadlineAndLostAuthorizationNeverRequestMorePermissions() {
        var policy = VPNRecoveryPolicy()
        policy.start(); policy.receive(.required, at: 0)
        XCTAssertEqual(policy.tick(at: 420, networkAvailable: false, canReconnect: true), .stop)
        policy.start(); policy.receive(.required, at: 200)
        XCTAssertEqual(policy.tick(at: 201, networkAvailable: true, canReconnect: false), .stop)
    }
    func testLongPreparationStillLeavesTimeForTunnelHandshake() {
        var policy = VPNRecoveryPolicy()
        policy.start(); policy.receive(.required, at: 0)
        XCTAssertEqual(policy.tick(at: 2, networkAvailable: true, canReconnect: true), .retry)
        policy.preparationCompleted(at: 300)
        XCTAssertEqual(policy.tick(at: 301, networkAvailable: true, canReconnect: true), .none)
        policy.receive(.restored, at: 305)
        XCTAssertFalse(policy.recovering)
    }
    func testStalledAttemptTimesOutAndFlappingDoesNotResetBudget() {
        var policy = VPNRecoveryPolicy()
        policy.start(); policy.receive(.required, at: 0)
        XCTAssertEqual(policy.tick(at: 2, networkAvailable: true, canReconnect: true), .retry)
        XCTAssertEqual(policy.tick(at: 42, networkAvailable: true, canReconnect: true), .none)
        XCTAssertEqual(policy.tick(at: 47, networkAvailable: true, canReconnect: true), .retry)
        policy.receive(.restored, at: 48)
        policy.receive(.required, at: 49)
        XCTAssertEqual(policy.attempts, 2)
        XCTAssertEqual(policy.tick(at: 64, networkAvailable: true, canReconnect: true), .retry)
        policy.receive(.restored, at: 65)
        policy.receive(.required, at: 130)
        XCTAssertEqual(policy.attempts, 0)
    }
}
