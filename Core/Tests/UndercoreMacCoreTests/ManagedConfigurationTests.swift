import Foundation
import XCTest
@testable import UndercoreMacCore

@MainActor
final class ManagedConfigurationTests: XCTestCase {
    private func configuration(_ revision: String? = "1", port: Int = 51820) throws -> ManagedConfiguration {
        let key = Data(repeating: 7, count: 32).base64EncodedString()
        let text = "[Interface]\nPrivateKey = \(key)\nAddress = 10.99.0.2/32\n[Peer]\nPublicKey = \(key)\nEndpoint = vpn.example.test:\(port)\nAllowedIPs = 0.0.0.0/0\n"
        return try ManagedConfiguration(data: Data(text.utf8), revisionHeader: revision)
    }

    func testUntrustedRevisionsAndMalformedConfigurationsAreRejected() throws {
        for header: String? in [nil, "", "0", "-1", "01", "+1", "1.0", " 1", "2147483648", "secret"] {
            XCTAssertThrowsError(try configuration(header))
        }
        XCTAssertThrowsError(try ManagedConfiguration(data: Data("PrivateKey=secret".utf8), revisionHeader: "2"))
    }

    func testNewExportIsNotCommittedUntilBackendAcceptsIt() async throws {
        let original = try configuration(), next = try configuration("2", port: 443)
        let updates = ManagedConfigurationRecovery(current: original)
        let data = try await updates.refresh { next }
        XCTAssertEqual(data, next.data)
        XCTAssertEqual(updates.current.data, original.data)
        updates.didReconnect()
        XCTAssertEqual(updates.current.revision, 2)
        XCTAssertEqual(updates.current.data, next.data)
    }

    func testUnchangedBytesAdvanceVersionWithoutReplacingParameters() async throws {
        let original = try configuration(), next = try configuration("2")
        let updates = ManagedConfigurationRecovery(current: original)
        let data = try await updates.refresh { next }
        XCTAssertNil(data)
        XCTAssertEqual(updates.current.revision, 2)
    }

    func testReplacementWithinSameNodeRevisionIsAccepted() async throws {
        let original = try configuration("3"), next = try configuration("3", port: 443)
        let updates = ManagedConfigurationRecovery(current: original)
        let data = try await updates.refresh { next }
        XCTAssertEqual(data, next.data)
    }

    func testDowngradeCannotReplaceAcceptedConfiguration() async throws {
        let original = try configuration("3"), stale = try configuration("2", port: 443)
        let updates = ManagedConfigurationRecovery(current: original)
        let data = try await updates.refresh { stale }
        XCTAssertNil(data)
        updates.didReconnect()
        XCTAssertEqual(updates.current.data, original.data)
        XCTAssertEqual(updates.current.revision, 3)
    }

    func testOnlyTwoChecksPerSessionWithMinimumInterval() async throws {
        var clock: TimeInterval = 0, calls = 0
        let original = try configuration()
        let updates = ManagedConfigurationRecovery(current: original, now: { clock })
        let fetch: @MainActor @Sendable () async throws -> ManagedConfiguration = { calls += 1; return original }
        _ = try await updates.refresh(fetch: fetch)
        clock = 59; _ = try await updates.refresh(fetch: fetch)
        XCTAssertEqual(calls, 1)
        clock = 60; _ = try await updates.refresh(fetch: fetch)
        clock = 3600; _ = try await updates.refresh(fetch: fetch)
        XCTAssertEqual(calls, 2)
    }

    func testRateLimitWaitsForRetryAfterAndRetainsCurrentData() async throws {
        var clock: TimeInterval = 0, calls = 0
        let original = try configuration()
        let updates = ManagedConfigurationRecovery(current: original, now: { clock })
        let data = try await updates.refresh { throw ClientError.server(status: 429, retryAfter: 300) }
        XCTAssertNil(data)
        clock = 61
        _ = try await updates.refresh { calls += 1; return original }
        XCTAssertEqual(calls, 0)
        clock = 300
        _ = try await updates.refresh { calls += 1; return original }
        XCTAssertEqual(calls, 1)
        XCTAssertEqual(updates.current.data, original.data)
    }

    func testTransientFailureKeepsCurrentButAccessFailuresStopRecovery() async throws {
        let original = try configuration()
        let updates = ManagedConfigurationRecovery(current: original)
        let data = try await updates.refresh { throw URLError(.notConnectedToInternet) }
        XCTAssertNil(data)
        XCTAssertEqual(updates.current.data, original.data)
        for error: ClientError in [.expiredSession, .wrongAccount, .unavailable, .unverified, .server(status: 403, retryAfter: nil)] {
            let updates = ManagedConfigurationRecovery(current: original)
            do { _ = try await updates.refresh { throw error }; XCTFail("Access failure swallowed") }
            catch let actual { XCTAssertEqual(actual as? ClientError, error) }
        }
    }

    func testTimeoutCancelsRequestAndKeepsCurrentConfiguration() async throws {
        let original = try configuration()
        let updates = ManagedConfigurationRecovery(current: original, timeout: .milliseconds(10))
        var cancelled = false
        let result = try await updates.refresh {
            do { try await Task.sleep(for: .seconds(30)); return original }
            catch { cancelled = true; throw error }
        }
        XCTAssertNil(result)
        XCTAssertTrue(cancelled)
        XCTAssertEqual(updates.current.data, original.data)
    }

    func testCancelledLateResponseCannotBeApplied() async throws {
        let original = try configuration(), next = try configuration("2", port: 443)
        let updates = ManagedConfigurationRecovery(current: original)
        var continuation: CheckedContinuation<ManagedConfiguration, Never>?
        let task = Task { try await updates.refresh { await withCheckedContinuation { continuation = $0 } } }
        while continuation == nil { await Task.yield() }
        task.cancel()
        continuation?.resume(returning: next)
        do { _ = try await task.value; XCTFail("Late response accepted") }
        catch { XCTAssertTrue(error is CancellationError) }
        updates.didReconnect()
        XCTAssertEqual(updates.current.data, original.data)
    }

    func testDiagnosticEventsDoNotContainConfigurationContent() {
        for outcome in [ManagedConfigurationRecovery.Outcome.checking, .unchanged, .available, .applied, .unavailable, .rejected, .accessDenied] {
            let code = VPNDiagnosticCode.configurationUpdate(outcome)
            XCTAssertEqual(VPNDiagnosticCode(wireValue: code.wireValue), code)
        }
        XCTAssertNil(VPNDiagnosticCode(wireValue: "configuration_update=PrivateKey=secret"))
    }
}
