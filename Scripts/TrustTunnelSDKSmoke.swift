import Foundation
import UndercoreMacCore
import VpnClientFramework
let endpoint = """
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
NativeLogger.setCallback { _, _ in }
NativeLogger.setLogLevel(.error)
let document = try TrustTunnelConfiguration(document: endpoint).runtimeDocument
if CommandLine.arguments.contains("--invalid") {
    let client = VpnClient(config: document.replacingOccurrences(of: "vpn_mode = \"general\"\n", with: ""), connectionInfoHandler: { _ in }, stateChangeHandler: { _ in })
    precondition(client == nil, "invalid document must be rejected")
    print("Invalid SDK configuration rejected without crashing")
} else {
    let client = VpnClient(config: document, connectionInfoHandler: { _ in }, stateChangeHandler: { _ in })
    precondition(client != nil, "generated runtime document must initialize SDK")
    _ = client?.stop()
    print("Generated runtime configuration accepted by real SDK; no tunnel started")
}
