import XCTest
@testable import UndercoreMacCore

final class TrustTunnelConfigurationTests: XCTestCase {
    private var document: String {
        """
        [endpoint]
        hostname = "vpn.example.test"
        addresses = ["192.0.2.10:9443"]
        username = "synthetic-user"
        password = "synthetic-test-password"
        has_ipv6 = false
        skip_verification = false
        certificate = ""
        upstream_protocol = "http2"
        anti_dpi = false
        dns_upstreams = []
        """
    }
    func testTransportEnvelopeAndLocalRoutingPolicy() throws {
        let data = try VPNTransportConfiguration.trustTunnelEnvelope(document)
        guard case .trustTunnel(let parsed) = try VPNTransportConfiguration.parse(data) else { return XCTFail() }
        XCTAssertEqual(parsed.remoteAddress, "192.0.2.10")
        XCTAssertTrue(parsed.runtimeDocument.contains("included_routes = []"))
        XCTAssertFalse(String(reflecting: parsed).contains("synthetic-test-password"))
    }
    func testRepeatedManifestProducesIdenticalBytesForRevisionComparison() throws {
        let first = try VPNTransportConfiguration.trustTunnelEnvelope(document)
        for _ in 0..<100 {
            XCTAssertEqual(try VPNTransportConfiguration.trustTunnelEnvelope(document), first)
        }
    }
    func testRejectsTLSBypassInjectedSettingsDuplicatesAndInvalidTypes() {
        for invalid in [
            document.replacingOccurrences(of: "skip_verification = false", with: "skip_verification = true"),
            document + "\n[listener.tun]\nmtu_size = 1",
            document + "\npassword = \"different\"",
            document.replacingOccurrences(of: "has_ipv6 = false", with: "has_ipv6 = 0"),
            document.replacingOccurrences(of: "certificate = \"\"", with: "certificate = \"invalid\""),
            document.replacingOccurrences(of: "192.0.2.10:9443", with: "user@192.0.2.10:9443"),
            document.replacingOccurrences(of: "dns_upstreams = []", with: "dns_upstreams = [\"https://example.test/dns-query\"]")
        ] { XCTAssertThrowsError(try TrustTunnelConfiguration(document: invalid)) }
    }
    func testCapabilitiesRequireExplicitOptIn() throws {
        let baseline = String(decoding: try JSONEncoder().encode(ConnectionCapabilities()), as: UTF8.self)
        XCTAssertFalse(baseline.contains("trusttunnel"))
        let experimental = String(decoding: try JSONEncoder().encode(ConnectionCapabilities(transports: [.amneziawg, .trusttunnel])), as: UTF8.self)
        XCTAssertTrue(experimental.contains("trusttunnel"))
    }
    func testRecoveryRequiresRepeatedNativeFailureAndIndependentInternetEvidence() {
        func observation(_ time: Double, _ outside: Bool, _ evidence: TunnelTransportEvidence) -> TunnelHealthObservation {
            TunnelHealthObservation(tunnelIP: false, tunnelName: false, directInternet: outside,
                networkAvailable: true, before: nil, after: nil, wallTime: 1000 + time,
                monotonicTime: time, transportEvidence: evidence)
        }
        var policy = TunnelHealthPolicy()
        XCTAssertEqual(policy.observe(observation(1, false, .upstreamUnavailable)), .source_unconfirmed)
        XCTAssertEqual(policy.observe(observation(2, true, .upstreamUnavailable)), .checking)
        XCTAssertEqual(policy.observe(observation(17, true, .upstreamUnavailable)), .checking)
        XCTAssertEqual(policy.observe(observation(32, true, .upstreamUnavailable)), .tunnel_unreachable)
        XCTAssertEqual(policy.observe(observation(33, true, .upstreamConnected)), .egress_unconfirmed)
    }

}
