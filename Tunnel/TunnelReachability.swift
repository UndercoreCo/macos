import Foundation
import Network
import NetworkExtension
import UndercoreMacCore

/// Fixed destinations only; outside-tunnel checks send TLS handshakes to IPs,
/// never DNS queries, credentials, user requests or application traffic.
final class TunnelReachability {
    struct Result {
        let codes: [VPNDiagnosticCode]
        let tunnelIP: Bool
        let tunnelName: Bool
        let dnsFailed: Bool
        let directInternet: Bool
    }
    private let queue: DispatchQueue
    private var cancelActive: (() -> Void)?
    init(queue: DispatchQueue) { self.queue = queue }
    func cancel() { cancelActive?(); cancelActive = nil }

    func check(provider: NEPacketTunnelProvider, completion: @escaping (Result) -> Void) {
        cancel()
        let tunnel: [(String, VPNDiagnosticCode.Probe)] = [
            ("1.1.1.1", .tls), ("8.8.8.8", .fallback_tls),
            ("example.com", .system_dns), ("www.apple.com", .fallback_name)
        ]
        let outside: [(String, VPNDiagnosticCode.Probe)] = [
            ("1.1.1.1", .outside_tls), ("8.8.8.8", .outside_fallback_tls)
        ]
        var results: [VPNDiagnosticCode.Probe: VPNDiagnosticCode.Outcome] = [:]
        var cancellations: [() -> Void] = []
        var cancelled = false
        var directStarted = false
        var completed = false
        cancelActive = { cancelled = true; cancellations.forEach { $0() } }
        func complete() {
            guard !cancelled, !completed else { return }
            completed = true
            self.cancelActive = nil
            let codes = (tunnel + outside).compactMap { item in results[item.1].map { VPNDiagnosticCode.probe(item.1, $0) } }
            completion(Result(codes: codes,
                tunnelIP: results[.tls] == .ok || results[.fallback_tls] == .ok,
                tunnelName: results[.system_dns] == .ok || results[.fallback_name] == .ok,
                dnsFailed: results[.system_dns] == .dns_failed && results[.fallback_name] == .dns_failed,
                directInternet: results[.outside_tls] == .ok || results[.outside_fallback_tls] == .ok))
        }
        func receive(_ label: VPNDiagnosticCode.Probe, _ outcome: VPNDiagnosticCode.Outcome) {
            guard !cancelled, !completed else { return }
            results[label] = outcome
            guard tunnel.allSatisfy({ results[$0.1] != nil }) else { return }
            // One working destination proves the tunnel carries application data.
            if tunnel.contains(where: { results[$0.1] == .ok }) { complete(); return }
            if !directStarted {
                directStarted = true
                for (host, label) in outside {
                    cancellations.append(self.legacyProbe(provider: provider, host: host, throughTunnel: false) { receive(label, $0) })
                }
            }
            if outside.allSatisfy({ results[$0.1] != nil }) { complete() }
        }
        for (host, label) in tunnel {
            if #available(macOS 15.0, *) {
                guard let interface = provider.virtualInterface else { receive(label, .failed); continue }
                cancellations.append(modernProbe(host: host, interface: interface) { receive(label, $0) })
            } else {
                cancellations.append(legacyProbe(provider: provider, host: host, throughTunnel: true) { receive(label, $0) })
            }
        }
    }

    @available(macOS 15.0, *)
    private func modernProbe(host: String, interface: NWInterface, completion: @escaping (VPNDiagnosticCode.Outcome) -> Void) -> () -> Void {
        let parameters = NWParameters.tls
        parameters.requiredInterface = interface
        let connection = NWConnection(host: NWEndpoint.Host(host), port: 443, using: parameters)
        var finished = false
        let finish: (VPNDiagnosticCode.Outcome?) -> Void = { outcome in
            guard !finished else { return }; finished = true
            connection.stateUpdateHandler = nil; connection.cancel()
            if let outcome { completion(outcome) }
        }
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: finish(.ok)
            case .failed(let error):
                if case .dns = error { finish(.dns_failed) } else { finish(.failed) }
            case .cancelled: finish(.failed)
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 8) { finish(.timeout) }
        return { finish(nil) }
    }

    // NEProvider's connection uses the provider's underlying route. The explicit
    // ThroughTunnel API is used only for the macOS 14 compatibility branch.
    private func legacyProbe(provider: NEPacketTunnelProvider, host: String, throughTunnel: Bool,
                             completion: @escaping (VPNDiagnosticCode.Outcome) -> Void) -> () -> Void {
        let endpoint = NWHostEndpoint(hostname: host, port: "443")
        let connection = throughTunnel
            ? provider.createTCPConnectionThroughTunnel(to: endpoint, enableTLS: true, tlsParameters: nil, delegate: nil)
            : provider.createTCPConnection(to: endpoint, enableTLS: true, tlsParameters: nil, delegate: nil)
        var observation: NSKeyValueObservation?
        var finished = false
        let finish: (VPNDiagnosticCode.Outcome?) -> Void = { outcome in
            guard !finished else { return }; finished = true
            observation?.invalidate(); observation = nil; connection.cancel()
            if let outcome { completion(outcome) }
        }
        observation = connection.observe(\.state, options: [.initial, .new]) { [queue] connection, _ in
            let state = connection.state
            queue.async {
                if state == .connected { finish(.ok) }
                else if state == .disconnected || state == .cancelled { finish(.failed) }
            }
        }
        queue.asyncAfter(deadline: .now() + 8) { finish(.timeout) }
        return { finish(nil) }
    }
}
