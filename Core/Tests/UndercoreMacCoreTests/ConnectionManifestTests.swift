import Foundation
import XCTest
@testable import UndercoreMacCore

@MainActor final class ConnectionManifestTests: XCTestCase {
    let device = "vpn_01M3FEB230BJPNX5WWB51891WZ"
    let now = ISO8601DateFormatter().date(from: "2028-01-01T00:00:00Z")!

    func payload() -> [String: Any] {
        let key = Data(repeating: 7, count: 32).base64EncodedString()
        return ["schema_version": 1, "device_id": device, "connection_id": "connection_1", "node_id": "awg31-lab",
                "protocol": "amneziawg", "state": "active", "expires_at": "2028-02-01T00:00:00.000Z", "revision": 1,
                "configuration": ["protocol": "amneziawg", "version": 1, "format": "awg-quick",
                    "data": "[Interface]\nPrivateKey = \(key)\nAddress = 10.99.0.2/32\n[Peer]\nPublicKey = \(key)\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0\n"]]
    }
    func decode(_ payload: [String: Any]) throws -> ManagedConfiguration {
        let dto = try JSONDecoder().decode(ConnectionManifest.self, from: JSONSerialization.data(withJSONObject: payload))
        return try dto.validated(deviceID: device, now: now)
    }
    func testManifestProducesEngineInputWithScopedRevision() throws {
        let value = try decode(payload())
        XCTAssertEqual(value.revisionScope, .connection(deviceID: device, connectionID: "connection_1"))
        XCTAssertEqual(value.revision, 1)
        XCTAssertNotNil(value.expiresAt)
        _ = try ProfileConfiguration.parse(value.data)
    }
    func testWrongDeviceStateVersionExpiryAndIdentityAreRejected() throws {
        let invalid: [(String, Any)] = [("device_id", "other"), ("connection_id", "../node"), ("node_id", ""),
            ("state", "disabled"), ("protocol", "trusttunnel"), ("schema_version", 2), ("schema_version", true),
            ("revision", 0), ("revision", "1"), ("expires_at", "2027-01-01T00:00:00.000Z"),
            ("expires_at", "2028-02-31T00:00:00.000Z"), ("expires_at", "2028-02-01T00:00:00+00:00")]
        for (key, value) in invalid {
            var data = payload(); data[key] = value
            XCTAssertThrowsError(try decode(data), key)
        }
    }
    func testUnknownEngineOrMalformedEngineInputIsRejected() throws {
        let invalid: [(String, Any)] = [("protocol", "trusttunnel"), ("version", 2), ("format", "trusttunnel-toml"),
            ("data", "not-a-profile"), ("data", String(repeating: "x", count: 65_537)), ("data", "[Interface]\0[Peer]")]
        for (key, value) in invalid {
            var data = payload(), config = data["configuration"] as! [String: Any]
            config[key] = value; data["configuration"] = config
            XCTAssertThrowsError(try decode(data), key)
        }
    }
    func testRecoveryDoesNotCompareRevisionsAcrossContractsOrConnections() async throws {
        let current = try decode(payload())
        let legacy = try ManagedConfiguration(data: current.data, revisionHeader: "999")
        var another = payload(); another["connection_id"] = "connection_2"; another["revision"] = 999
        let other = try decode(another)
        for (first, next) in [(legacy, current), (current, legacy), (current, other)] {
            let recovery = ManagedConfigurationRecovery(current: first)
            var outcome: ManagedConfigurationRecovery.Outcome?
            recovery.onOutcome = { outcome = $0 }
            let result = try await recovery.refresh { next }
            XCTAssertNil(result)
            XCTAssertEqual(outcome, .rejected)
            XCTAssertEqual(recovery.current.revisionScope, first.revisionScope)
        }
    }
    func testManifestRevisionMustIncreaseWhenParametersOrExpiryChange() async throws {
        let current = try decode(payload())
        var changed = payload(); changed["expires_at"] = "2028-03-01T00:00:00.000Z"
        let sameRevision = try decode(changed)
        let recovery = ManagedConfigurationRecovery(current: current)
        var outcome: ManagedConfigurationRecovery.Outcome?
        recovery.onOutcome = { outcome = $0 }
        _ = try await recovery.refresh { sameRevision }
        XCTAssertEqual(outcome, .rejected)
        changed["revision"] = 2
        let next = try decode(changed)
        let accepted = ManagedConfigurationRecovery(current: current)
        _ = try await accepted.refresh { next }
        XCTAssertEqual(accepted.current.expiresAt, next.expiresAt)
        XCTAssertEqual(accepted.current.revision, 2)
    }
    func testRealConfigurationChangeWaitsForBackendConfirmation() async throws {
        let current = try decode(payload())
        var changed = payload(), config = changed["configuration"] as! [String: Any]
        config["data"] = (config["data"] as! String).replacingOccurrences(of: ":51820", with: ":443")
        changed["configuration"] = config; changed["revision"] = 2
        let next = try decode(changed)
        let recovery = ManagedConfigurationRecovery(current: current)
        let result = try await recovery.refresh { next }
        XCTAssertEqual(result, next.data)
        XCTAssertEqual(recovery.current.revision, 1)
        recovery.didReconnect()
        XCTAssertEqual(recovery.current.revision, 2)
    }
    func testNodeSwitchKeepsDeviceScopeAndAcceptsNewKeysAddressAndEndpoint() async throws {
        let current = try decode(payload())
        var changed = payload(), config = changed["configuration"] as! [String: Any]
        let oldKey = Data(repeating: 7, count: 32).base64EncodedString()
        let newKey = Data(repeating: 8, count: 32).base64EncodedString()
        config["data"] = (config["data"] as! String)
            .replacingOccurrences(of: oldKey, with: newKey)
            .replacingOccurrences(of: "10.99.0.2/32", with: "10.98.0.2/32")
            .replacingOccurrences(of: "vpn.example.test:51820", with: "second.example.test:44537")
        changed["configuration"] = config
        changed["node_id"] = "awg20-managed"
        changed["revision"] = 2
        let candidate = try decode(changed)
        let recovery = ManagedConfigurationRecovery(current: current)
        let engineInput = try await recovery.refresh { candidate }
        XCTAssertEqual(engineInput, candidate.data)
        XCTAssertEqual(recovery.current.data, current.data)
        recovery.didReconnect()
        XCTAssertEqual(recovery.current.data, candidate.data)
        XCTAssertEqual(recovery.current.revisionScope, current.revisionScope)
        XCTAssertEqual(recovery.current.revision, 2)
    }

    func recoveryConfiguration() throws -> ManagedConfiguration {
        let value = try decode(payload())
        return try ManagedConfiguration(data: value.data, revision: value.revision,
            revisionScope: value.revisionScope, expiresAt: value.expiresAt, automaticRecoveryAllowed: true)
    }
    func testRetriesWithoutTunnelEvidenceNeverRequestAnotherServer() async throws {
        let original = try recoveryConfiguration()
        let recovery = ManagedConfigurationRecovery(current: original)
        var moves = 0, reads = 0
        for attempt in 1...5 {
            _ = try await recovery.refresh(attempt: attempt, recover: { _ in
                moves += 1; return original
            }, fetch: { reads += 1; return original })
        }
        XCTAssertEqual(moves, 0)
        XCTAssertEqual(reads, 1) // Repeated failures retain the existing API cooldown.
        XCTAssertEqual(recovery.current.revision, original.revision)
    }
    func testAlternativeOnlyAfterLocalRetryAndOnlyOneMovePerSession() async throws {
        let original = try recoveryConfiguration()
        var changed = payload(), config = changed["configuration"] as! [String: Any]
        config["data"] = (config["data"] as! String).replacingOccurrences(of: ":51820", with: ":443")
        changed["configuration"] = config; changed["revision"] = 2
        let next = try decode(changed)
        var requests: [Int] = [], reads = 0
        let recovery = ManagedConfigurationRecovery(current: original)
        let alternate: @MainActor @Sendable (Int) async throws -> ManagedConfiguration = { revision in
            requests.append(revision); return next
        }
        let read: @MainActor @Sendable () async throws -> ManagedConfiguration = { reads += 1; return original }
        _ = try await recovery.refresh(attempt: 1, allowAlternative: true, recover: alternate, fetch: read)
        XCTAssertTrue(requests.isEmpty)
        let result = try await recovery.refresh(attempt: 2, allowAlternative: true, recover: alternate, fetch: read)
        XCTAssertEqual(result, next.data)
        XCTAssertEqual(requests, [1]); XCTAssertEqual(reads, 1)
        // Backend rejected the first application: retry the already accepted candidate.
        let retry = try await recovery.refresh(attempt: 3, allowAlternative: true, recover: alternate, fetch: read)
        XCTAssertEqual(retry, next.data)
        recovery.didReconnect()
        _ = try await recovery.refresh(attempt: 3, allowAlternative: true, recover: alternate, fetch: read)
        XCTAssertEqual(requests, [1])
    }
    func testAmbiguousRecoveryRetriesSameRevisionWithBoundedBudget() async throws {
        let original = try recoveryConfiguration()
        let recovery = ManagedConfigurationRecovery(current: original)
        var requests: [Int] = []
        for attempt in 2...6 {
            _ = try await recovery.refresh(attempt: attempt, allowAlternative: true, recover: { revision in
                requests.append(revision); throw URLError(.timedOut)
            }, fetch: { original })
        }
        XCTAssertEqual(requests, [1, 1])
        XCTAssertEqual(recovery.current.revision, 1)
    }
    func testRecoveryRequiresOptInAndRespectsServerCooldown() async throws {
        let plain = try decode(payload()), enabled = try recoveryConfiguration()
        var clock: TimeInterval = 0, calls = 0
        let disabled = ManagedConfigurationRecovery(current: plain)
        _ = try await disabled.refresh(attempt: 2, allowAlternative: true, recover: { _ in calls += 1; return plain }, fetch: { plain })
        XCTAssertEqual(calls, 0)
        let recovery = ManagedConfigurationRecovery(current: enabled, now: { clock })
        _ = try await recovery.refresh(attempt: 2, allowAlternative: true, recover: { _ in
            calls += 1; throw ClientError.server(status: 429, retryAfter: 1800)
        }, fetch: { enabled })
        clock = 60
        _ = try await recovery.refresh(attempt: 3, allowAlternative: true, recover: { _ in calls += 1; return enabled }, fetch: { enabled })
        XCTAssertEqual(calls, 1)
    }

    func testPendingTransferPollsSameRevisionThenAcceptsResult() async throws {
        let original = try recoveryConfiguration()
        var changed = payload(); changed["revision"] = 2
        let next = try decode(changed)
        var requests: [Int] = [], waits: [Duration] = []
        let recovery = ManagedConfigurationRecovery(current: original, sleep: { waits.append($0) })
        _ = try await recovery.refresh(attempt: 2, allowAlternative: true, recover: { revision in
            requests.append(revision)
            if requests.count < 3 { throw ClientError.recoveryPending(retryAfter: 30) }
            return next
        }, fetch: { original })
        XCTAssertEqual(requests, [1, 1, 1])
        XCTAssertEqual(waits, [.seconds(30), .seconds(30)])
        XCTAssertEqual(recovery.current.revision, 2)
    }
    func testPendingTransferIsBoundedAndCancellationStopsPolling() async throws {
        let original = try recoveryConfiguration()
        var calls = 0
        let recovery = ManagedConfigurationRecovery(current: original, sleep: { _ in })
        _ = try await recovery.refresh(attempt: 2, allowAlternative: true, recover: { _ in
            calls += 1; throw ClientError.recoveryPending(retryAfter: 30)
        }, fetch: { original })
        XCTAssertEqual(calls, 12)
        XCTAssertEqual(recovery.current.revision, 1)
        let cancelled = ManagedConfigurationRecovery(current: original, sleep: { _ in throw CancellationError() })
        do {
            _ = try await cancelled.refresh(attempt: 2, allowAlternative: true, recover: { _ in
                throw ClientError.recoveryPending(retryAfter: 30)
            }, fetch: { original })
            XCTFail("Cancellation was swallowed")
        } catch { XCTAssertTrue(error is CancellationError) }
    }

}
