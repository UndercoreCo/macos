#if TRUSTTUNNEL_EXPERIMENTAL
import Foundation
import NetworkExtension
import UndercoreMacCore
import VpnClientFramework

/// Official SDK uses NEPacketTunnelFlow; it never receives permission to set global routes.
final class TrustTunnelEngine: PacketTunnelEngine {
    private weak var provider: NEPacketTunnelProvider?
    private let configuration: TrustTunnelConfiguration
    private let queue: DispatchQueue
    private var client: VpnClient?
    private var completion: ((Error?) -> Void)?
    private var generation = UUID()
    private var running = false
    private(set) var transportEvidence = TunnelTransportEvidence.unknown

    init(provider: NEPacketTunnelProvider, configuration: TrustTunnelConfiguration, queue: DispatchQueue) {
        self.provider = provider; self.configuration = configuration; self.queue = queue
    }
    private var failure: NSError { NSError(domain: "UndercoreTunnel", code: 2) }

    func start(completion: @escaping (Error?) -> Void) {
        guard let provider, !running else { completion(failure); return }
        self.completion = completion; running = true
        let token = UUID(); generation = token
        // Even error logs can contain endpoints/credentials. Keep only our structured diagnostics.
        NativeLogger.setCallback { _, _ in }
        NativeLogger.setLogLevel(.error)
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: configuration.remoteAddress)
        let ipv4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [.default()]
        let ipv6 = NEIPv6Settings(addresses: ["fd00::1"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [.default()]
        // Capture IPv6 even on an IPv4-only node: unsupported traffic must not escape the tunnel.
        settings.ipv4Settings = ipv4; settings.ipv6Settings = ipv6
        let dns = NEDNSSettings(servers: ["1.1.1.1", "9.9.9.9"])
        dns.matchDomains = [""]; settings.dnsSettings = dns; settings.mtu = 1350
        provider.setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                guard self.running, self.generation == token else { return }
                guard error == nil, let provider = self.provider else { self.fail(); return }
                self.client = VpnClient(config: self.configuration.runtimeDocument,
                    connectionInfoHandler: { _ in }, // Never collect browsing history.
                    stateChangeHandler: { [weak self] state in
                        guard let self else { return }
                        self.queue.async { self.changed(Int(state), token: token) }
                    })
                guard self.client?.start(provider.packetFlow) == true else { self.fail(); return }
            }
        }
        queue.asyncAfter(deadline: .now() + 25) { [weak self] in
            guard let self, self.generation == token, self.completion != nil else { return }
            self.fail()
        }
    }
    private func changed(_ state: Int, token: UUID) {
        guard running, token == generation else { return }
        switch state {
        case 0: fail()
        case 2:
            transportEvidence = .upstreamConnected
            provider?.reasserting = false
            let callback = completion; completion = nil; callback?(nil)
        // Keep NE connected while our common health policy evaluates the failure.
        // Setting reasserting here would suspend the app status poller.
        case 3, 4:
            transportEvidence = .upstreamUnavailable
        case 5:
            transportEvidence = .unknown
        default: break
        }
    }
    private func fail() {
        let callback = completion; completion = nil
        stop { }
        if let callback { callback(failure) }
        else { provider?.cancelTunnelWithError(failure) }
    }
    func stop(completion: @escaping () -> Void) {
        running = false; transportEvidence = .unknown; generation = UUID()
        let pending = self.completion; self.completion = nil
        _ = client?.stop(); client = nil; provider?.reasserting = false
        pending?(failure); completion()
    }
    func sleep() { client?.notify_sleep() }
    func wake() { client?.notify_wake() }
}
#endif
