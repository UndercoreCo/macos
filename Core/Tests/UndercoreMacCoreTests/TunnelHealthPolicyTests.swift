import Foundation
import XCTest
@testable import UndercoreMacCore

final class TunnelHealthPolicyTests: XCTestCase {
    private func counter(_ time: UInt64 = 0, tx: UInt64 = 100, rx: UInt64 = 100) -> TunnelCounters {
        TunnelCounters.parse("last_handshake_time_sec=\(time)\ntx_bytes=\(tx)\nrx_bytes=\(rx)\n")!
    }
    private func sample(_ at: Double, ip: Bool = false, name: Bool = false, dns: Bool = false,
                        direct: Bool = true, network: Bool? = true,
                        after: TunnelCounters? = nil, missing: Bool = false) -> TunnelHealthObservation {
        .init(tunnelIP: ip, tunnelName: name, dnsFailed: dns, directInternet: direct,
              networkAvailable: network, before: missing ? nil : counter(),
              after: missing ? nil : (after ?? counter(tx: 200)), wallTime: 1000, monotonicTime: at)
    }
    func testHandshakeFreshnessIncludesClockAndAge() {
        XCTAssertFalse(counter().hasFreshHandshake(at: 1000))
        XCTAssertFalse(counter(819).hasFreshHandshake(at: 1000))
        XCTAssertTrue(counter(820).hasFreshHandshake(at: 1000))
        XCTAssertTrue(counter(1000).hasFreshHandshake(at: 1000))
        XCTAssertFalse(counter(1001).hasFreshHandshake(at: 1000))
    }
    func testOneWorkingNameProvesTransportEvenIfIPTargetsBlocked() {
        var p = TunnelHealthPolicy()
        XCTAssertEqual(p.observe(sample(0, name: true)), .ok)
        XCTAssertEqual(p.failures, 0)
    }
    func testNamesOrDNSCannotCauseServerRecovery() {
        var p = TunnelHealthPolicy()
        for i in 0..<10 {
            XCTAssertEqual(p.observe(sample(Double(i * 20), ip: true)), .name_unavailable)
        }
        XCTAssertEqual(p.observe(sample(210, ip: true, dns: true)), .dns)
        XCTAssertEqual(p.failures, 0)
    }
    func testMissingPhysicalNetworkNeverCountsAsTunnelFailure() {
        var p = TunnelHealthPolicy()
        for i in 0..<10 {
            XCTAssertEqual(p.observe(sample(Double(i * 20), direct: false, network: false)), .network_unavailable)
        }
        XCTAssertEqual(p.failures, 0)
    }
    func testBothPathsFailIsUnknownNotProvenProviderOrTunnelFailure() {
        var p = TunnelHealthPolicy()
        for i in 0..<10 {
            XCTAssertEqual(p.observe(sample(Double(i * 20), direct: false)), .source_unconfirmed)
        }
        XCTAssertEqual(p.failures, 0)
    }
    func testMissingResetOrFutureCountersCannotAuthorizeRecovery() {
        var p = TunnelHealthPolicy()
        XCTAssertEqual(p.observe(sample(0, missing: true)), .degraded)
        XCTAssertEqual(p.observe(sample(20, after: counter(tx: 1, rx: 1))), .degraded)
        XCTAssertEqual(p.observe(sample(40, after: counter(1001))), .degraded)
    }
    func testFreshHandshakeOrIncomingDataMeansEgressUnknown() {
        var p = TunnelHealthPolicy()
        XCTAssertEqual(p.observe(sample(0, after: counter(950))), .egress_unconfirmed)
        XCTAssertEqual(p.observe(sample(20, after: counter(1, tx: 200, rx: 101))), .egress_unconfirmed)
        XCTAssertEqual(p.failures, 0)
    }
    func testRecoveryNeedsDistinctConsecutiveSamplesAndDuration() {
        var p = TunnelHealthPolicy()
        XCTAssertEqual(p.observe(sample(0)), .checking)
        for _ in 0..<30 { XCTAssertEqual(p.observe(sample(0)), .checking) }
        XCTAssertEqual(p.failures, 1)
        XCTAssertEqual(p.observe(sample(1)), .checking)
        XCTAssertEqual(p.observe(sample(2)), .checking)
        XCTAssertEqual(p.observe(sample(30)), .tunnel_unreachable)
        XCTAssertEqual(p.observe(sample(40, name: true)), .ok)
        XCTAssertEqual(p.failures, 0)
    }
    func testUnknownNetworkAndLongGapsResetFailureBudget() {
        var p = TunnelHealthPolicy()
        _ = p.observe(sample(0)); _ = p.observe(sample(20))
        _ = p.observe(sample(40, direct: false))
        XCTAssertEqual(p.observe(sample(60)), .checking)
        XCTAssertEqual(p.failures, 1)
        XCTAssertEqual(p.observe(sample(130)), .checking)
        XCTAssertEqual(p.failures, 1)
    }
    func testNewHealthCodesSurviveBoundedIPC() throws {
        let id = UUID(), run = UUID()
        let codes: [VPNDiagnosticCode] = [.health(.source_unconfirmed), .probe(.outside_tls, .timeout),
            .probe(.fallback_name, .dns_failed), .probe(.handshake_fresh, .failed), .probe(.rx_progress, .ok)]
        let reply = TunnelStatusReply(requestID: id, runID: run, checkID: UUID(), codes: codes)
        let decoded = TunnelStatusReply.decode(try JSONEncoder().encode(reply), requestID: id, runID: run)
        XCTAssertEqual(decoded?.codes, codes.map(\.wireValue))
    }
}
