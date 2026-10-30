import Foundation
import XCTest
@testable import UndercoreMacCore

final class VPNRecoveryCoordinatorTests: XCTestCase {
    @MainActor
    func testAlternativeRequiresFreshEvidenceAndIsResetByNetworkOrSleep() {
        var clock: TimeInterval = 0
        let coordinator = VPNRecoveryCoordinator(backend: RecoveryBackend(), now: { clock })
        let id = UUID()
        coordinator.start(); coordinator.networkAvailable = true
        coordinator.observe(.init(sessionID: id, kind: .began))
        coordinator.observe(.init(sessionID: id, kind: .code(.health(.degraded))))
        XCTAssertFalse(coordinator.canRequestAlternative)
        coordinator.observe(.init(sessionID: UUID(), kind: .code(.health(.tunnel_unreachable))))
        XCTAssertFalse(coordinator.canRequestAlternative)
        coordinator.observe(.init(sessionID: id, kind: .code(.health(.tunnel_unreachable))))
        XCTAssertTrue(coordinator.canRequestAlternative)
        clock = 121
        XCTAssertFalse(coordinator.canRequestAlternative)
        coordinator.observe(.init(sessionID: id, kind: .code(.health(.tunnel_unreachable))))
        coordinator.networkAvailable = false; coordinator.networkAvailable = true
        XCTAssertFalse(coordinator.canRequestAlternative)
        coordinator.observe(.init(sessionID: id, kind: .code(.health(.tunnel_unreachable))))
        coordinator.setSleeping(true); coordinator.setSleeping(false)
        XCTAssertFalse(coordinator.canRequestAlternative)
        coordinator.observe(.init(sessionID: id, kind: .code(.health(.tunnel_unreachable))))
        coordinator.networkChanged()
        XCTAssertFalse(coordinator.canRequestAlternative)
        coordinator.observe(.init(sessionID: id, kind: .code(.health(.tunnel_unreachable))))
        coordinator.observe(.init(sessionID: UUID(), kind: .began))
        XCTAssertFalse(coordinator.canRequestAlternative)
        coordinator.cancel()
    }
    @MainActor
    func testAutomaticRecoveryUsesOnlyAuthorizedEntryPointAndRecordsAttempts() {
        var clock: TimeInterval = 0
        let backend = RecoveryBackend()
        let coordinator = VPNRecoveryCoordinator(backend: backend, now: { clock })
        let session = UUID()
        var codes: [VPNDiagnosticCode] = []
        coordinator.onDiagnosticEvent = { event in
            XCTAssertEqual(event.sessionID, session)
            if case .code(let code) = event.kind { codes.append(code) }
        }
        coordinator.observe(.init(sessionID: session, kind: .began))
        coordinator.networkAvailable = true
        coordinator.start()
        coordinator.receive(.required)
        clock = 2; coordinator.tick()
        XCTAssertEqual(backend.reconnects, 1)
        XCTAssertEqual(backend.interactiveConnects, 0)
        XCTAssertEqual(codes, [.recoveryAttempt(1)])
        coordinator.cancel()
        clock = 100; coordinator.receive(.attemptFailed); coordinator.tick()
        XCTAssertEqual(backend.reconnects, 1)
    }
    @MainActor
    func testLostHelperCannotEscalateToInteractiveConnect() {
        var clock: TimeInterval = 0
        let backend = RecoveryBackend()
        let coordinator = VPNRecoveryCoordinator(backend: backend, now: { clock })
        var exhausted = 0
        coordinator.onExhausted = { exhausted += 1 }
        coordinator.networkAvailable = true
        coordinator.start(); coordinator.receive(.required)
        backend.canReconnect = false
        clock = 2; coordinator.tick()
        XCTAssertEqual(exhausted, 1)
        XCTAssertEqual(backend.reconnects, 0)
        XCTAssertEqual(backend.interactiveConnects, 0)
    }
    @MainActor
    func testWakeGivesCurrentTunnelTimeToPassFreshCheck() {
        var clock: TimeInterval = 0
        let backend = RecoveryBackend()
        let coordinator = VPNRecoveryCoordinator(backend: backend, now: { clock })
        coordinator.networkAvailable = true
        coordinator.start(); coordinator.receive(.required)
        coordinator.setSleeping(true)
        clock = 30; coordinator.setSleeping(false); coordinator.tick()
        XCTAssertEqual(backend.reconnects, 0)
        clock = 35; coordinator.receive(.restored)
        clock = 50; coordinator.tick()
        XCTAssertEqual(backend.reconnects, 0)
        XCTAssertFalse(coordinator.recovering)
    }
    @MainActor
    func testManagedRecoveryPausesBeforeFetchingAndNeverUsesInteractiveConnect() async {
        var clock: TimeInterval = 0
        let backend = RecoveryBackend()
        let coordinator = VPNRecoveryCoordinator(backend: backend, now: { clock })
        coordinator.networkAvailable = true
        var sequence: [String] = []
        backend.onPrepare = { sequence.append("pause") }
        backend.onReconnect = { sequence.append("reconnect") }
        coordinator.configurationForRecovery = { sequence.append("fetch"); return Data([1, 2, 3]) }
        coordinator.onReconnectSucceeded = { sequence.append("accepted") }
        coordinator.start(); coordinator.receive(.required)
        clock = 2; coordinator.tick()
        for _ in 0..<100 where sequence.count < 4 { await Task.yield() }
        XCTAssertEqual(sequence, ["pause", "fetch", "reconnect", "accepted"])
        XCTAssertEqual(backend.updatedData, Data([1, 2, 3]))
        XCTAssertEqual(backend.interactiveConnects, 0)
        coordinator.cancel()
    }

    @MainActor
    func testUserCancelOrRestoredHealthPreventsDelayedUpdateFromRestarting() async {
        for restore in [false, true] {
            var clock: TimeInterval = 0
            let backend = RecoveryBackend()
            let coordinator = VPNRecoveryCoordinator(backend: backend, now: { clock })
            coordinator.networkAvailable = true
            var continuation: CheckedContinuation<Data?, Never>?
            coordinator.configurationForRecovery = { await withCheckedContinuation { continuation = $0 } }
            coordinator.start(); coordinator.receive(.required)
            clock = 2; coordinator.tick()
            for _ in 0..<100 where continuation == nil { await Task.yield() }
            XCTAssertNotNil(continuation)
            if restore { coordinator.receive(.restored) } else { coordinator.cancel() }
            continuation?.resume(returning: Data([1]))
            for _ in 0..<20 { await Task.yield() }
            XCTAssertEqual(backend.reconnects, 0)
            XCTAssertEqual(backend.interactiveConnects, 0)
            coordinator.cancel()
        }
    }

    @MainActor
    func testSingleFlightAndDeniedAccessStopWithoutReconnect() async {
        var clock: TimeInterval = 0
        let backend = RecoveryBackend()
        let coordinator = VPNRecoveryCoordinator(backend: backend, now: { clock })
        coordinator.networkAvailable = true
        var requests = 0, failures = 0
        var continuation: CheckedContinuation<Data?, Error>?
        coordinator.configurationForRecovery = {
            requests += 1
            return try await withCheckedThrowingContinuation { continuation = $0 }
        }
        coordinator.onPreparationFailure = { _ in failures += 1 }
        coordinator.start(); coordinator.receive(.required)
        clock = 2; coordinator.tick()
        for _ in 0..<100 where continuation == nil { await Task.yield() }
        clock = 100; coordinator.tick(); coordinator.tick()
        XCTAssertEqual(requests, 1)
        continuation?.resume(throwing: ClientError.expiredSession)
        for _ in 0..<100 where failures == 0 { await Task.yield() }
        XCTAssertEqual(failures, 1)
        XCTAssertEqual(backend.reconnects, 0)
        XCTAssertFalse(coordinator.recovering)
    }

    @MainActor
    func testSleepCancelsPendingRefreshWithoutRestartingTunnel() async {
        var clock: TimeInterval = 0
        let backend = RecoveryBackend()
        let coordinator = VPNRecoveryCoordinator(backend: backend, now: { clock })
        coordinator.networkAvailable = true
        var continuation: CheckedContinuation<Data?, Never>?
        coordinator.configurationForRecovery = { await withCheckedContinuation { continuation = $0 } }
        coordinator.start(); coordinator.receive(.required)
        clock = 2; coordinator.tick()
        for _ in 0..<100 where continuation == nil { await Task.yield() }
        coordinator.setSleeping(true)
        continuation?.resume(returning: Data([1]))
        for _ in 0..<20 { await Task.yield() }
        XCTAssertEqual(backend.reconnects, 0)
        coordinator.cancel()
    }

}

@MainActor
private final class RecoveryBackend: VPNBackend {
    var onRecoveryEvent: ((VPNRecoveryEvent) -> Void)?
    var onDiagnosticEvent: ((VPNDiagnosticEvent) -> Void)?
    var onStateChange: ((VPNState, String?) -> Void)?
    var canReconnect = true
    var supportsConfigurationUpdates = true
    var onPrepare: (() -> Void)?
    var onReconnect: (() -> Void)?
    var updatedData: Data?
    func prepareForConfigurationRefresh() async throws { onPrepare?() }
    func reconnect(configuration: Data?) async throws {
        updatedData = configuration
        reconnects += 1
        onReconnect?()
    }
    var reconnects = 0
    var interactiveConnects = 0
    func reconnect() throws { reconnects += 1 }
    func connect(configuration: Data, profile: ConnectionProfile) async throws { interactiveConnects += 1 }
    func handleSystemEvent(_ event: VPNSystemEvent) {}
    func requestHealthCheck() {}
    func restore() async throws {}
    func remove() async throws {}
    func disconnect() async {}
}
