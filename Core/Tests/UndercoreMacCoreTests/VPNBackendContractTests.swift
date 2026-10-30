import Foundation
import XCTest
@testable import UndercoreMacCore

final class VPNBackendContractTests: XCTestCase {
    func testRawAdapterPayloadRejectsSecretsAndRoundTripsTypedEvents() {
        let events: [VPNDiagnosticCode] = [
            .lifecycle(.reasserting), .health(.unavailable), .recoveryAttempt(3), .lifecycle(.recovery_exhausted),
            .stage(.transport, succeeded: false, milliseconds: 125, errno: 51),
            .probe(.fallback_tls, .timeout), .counters(handshake: true, sent: 20, received: 80),
            .flow(read: 1, written: 2, unknownIP: 0, errors: 0, sendErrors: 3, errno: 51)
        ]
        for event in events { XCTAssertEqual(VPNDiagnosticCode(wireValue: event.wireValue), event) }
        for raw in ["recovery_attempt=4", "recovery_attempt=0", "recovery_attempt=01", "private_key=SECRET", "step_transport=SECRET,0,0", "stats=2,1,1", "stats=1,-1,3", "flow=0,0,0,0,0,999999999999999999999999", "error endpoint=SECRET"] {
            XCTAssertNil(VPNDiagnosticCode(wireValue: raw))
        }
    }

    func testLateEventsCannotPolluteNextSessionOrReopenClosedSession() {
        var recorder = DiagnosticSessionRecorder()
        let old = UUID(), current = UUID()
        _ = recorder.receive(.init(sessionID: old, kind: .began))
        let replaced = recorder.receive(.init(sessionID: current, kind: .began))
        XCTAssertEqual(replaced.count, 2)
        XCTAssertEqual(replaced.first?.events.last?.value, "previous_session_incomplete")
        XCTAssertTrue(recorder.receive(.init(sessionID: old, kind: .code(.health(.ok)))).isEmpty)
        XCTAssertTrue(recorder.receive(.init(sessionID: old, kind: .ended)).isEmpty)
        XCTAssertEqual(recorder.report?.id, current)
        _ = recorder.receive(.init(sessionID: current, kind: .ended))
        XCTAssertTrue(recorder.receive(.init(sessionID: current, kind: .code(.health(.ok)))).isEmpty)
        XCTAssertTrue(recorder.receive(.init(sessionID: current, kind: .began)).isEmpty)
        XCTAssertTrue(recorder.receive(.init(sessionID: current, kind: .ended)).isEmpty)
        XCTAssertEqual(recorder.report?.events.last?.value, "closed")
    }

    func testRateLimitsAndBoundariesAreSharedByAllAdapters() {
        var recorder = DiagnosticSessionRecorder()
        let id = UUID(), now = Date()
        _ = recorder.receive(.init(sessionID: id, kind: .began, at: now))
        let sample: VPNDiagnosticCode = .counters(handshake: true, sent: 10, received: 20)
        XCTAssertEqual(recorder.receive(.init(sessionID: id, kind: .code(sample), at: now)).count, 1)
        XCTAssertTrue(recorder.receive(.init(sessionID: id, kind: .code(sample), at: now.addingTimeInterval(2))).isEmpty)
        XCTAssertEqual(recorder.receive(.init(sessionID: id, kind: .code(sample), at: now.addingTimeInterval(15))).count, 1)
        XCTAssertTrue(recorder.receive(.init(sessionID: id, kind: .code(.lifecycle(.closed)))).isEmpty)
        XCTAssertFalse(recorder.report?.isFinished ?? true)
    }

    func testUnavailableHealthNeverClaimsVerifiedInternet() {
        var health = ConnectionHealth()
        XCTAssertTrue(health.receive(VPNDiagnosticCode.health(.unavailable).wireValue))
        XCTAssertEqual(health.state, .unverified)
        XCTAssertTrue(health.receive(VPNDiagnosticCode.health(.ok).wireValue))
        XCTAssertEqual(health.state, .connected)
    }

    @MainActor
    func testBackendCanFeedCommonHistoryWithoutKnowingStorage() async throws {
        let backend: any VPNBackend = FakeBackend()
        var recorder = DiagnosticSessionRecorder()
        backend.onDiagnosticEvent = { _ = recorder.receive($0) }
        try await backend.connect(configuration: Data(), profile: ConnectionProfile(name: "Test"))
        XCTAssertEqual(recorder.report?.events.map(\.value), ["starting", "connected", "health=ok"])
        await backend.disconnect()
        XCTAssertEqual(recorder.report?.events.last?.value, "closed")
        XCTAssertTrue(recorder.report?.isFinished ?? false)
    }

    @MainActor
    func testUnsupportedBackendCannotRefreshOrEscalateAuthorization() async {
        let backend: any VPNBackend = FakeBackend()
        var events = 0
        backend.onDiagnosticEvent = { _ in events += 1 }
        XCTAssertFalse(backend.supportsConfigurationUpdates)
        do { try await backend.prepareForConfigurationRefresh(); XCTFail("Unsupported refresh accepted") }
        catch { XCTAssertTrue(error is VPNRecoveryError) }
        do { try await backend.reconnect(configuration: Data([1])); XCTFail("Unsupported replacement accepted") }
        catch { XCTAssertTrue(error is VPNRecoveryError) }
        XCTAssertEqual(events, 0)
    }

    @MainActor
    func testEmitterDropsCallbacksFromPreviousAttempt() async {
        let emitter = VPNDiagnosticEmitter()
        var events: [VPNDiagnosticEvent] = []
        emitter.onEvent = { events.append($0) }
        let old = emitter.begin(), current = emitter.begin()
        emitter.record(.health(.ok), sessionID: old)
        emitter.end(sessionID: old)
        XCTAssertEqual(events.count, 2)
        XCTAssertEqual(emitter.sessionID, current)
        emitter.record(.health(.dns), sessionID: current)
        emitter.end(sessionID: current)
        emitter.end(sessionID: current)
        XCTAssertEqual(events.count, 4)
        XCTAssertNil(emitter.sessionID)
    }
}

@MainActor
private final class FakeBackend: VPNBackend {
    var onRecoveryEvent: ((VPNRecoveryEvent) -> Void)?
    var onStateChange: ((VPNState, String?) -> Void)?
    private let events = VPNDiagnosticEmitter()
    var onDiagnosticEvent: ((VPNDiagnosticEvent) -> Void)? {
        get { events.onEvent }
        set { events.onEvent = newValue }
    }
    func handleSystemEvent(_ event: VPNSystemEvent) {}
    func requestHealthCheck() {}
    func restore() async throws {}
    func remove() async throws {}
    func connect(configuration: Data, profile: ConnectionProfile) async throws {
        let id = events.begin()
        events.record(.lifecycle(.connected), sessionID: id)
        events.record(.health(.ok), sessionID: id)
        onStateChange?(.connected, nil)
    }
    func disconnect() async {
        guard let id = events.sessionID else { return }
        events.record(.lifecycle(.stop_requested), sessionID: id)
        events.end(sessionID: id)
        onStateChange?(.disconnected, nil)
    }
}
