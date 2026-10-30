import Foundation
import NetworkExtension
import UndercoreMacCore
import WireGuardKit

/// Data-plane boundary; provider health, recovery and diagnostics remain transport-neutral.
protocol PacketTunnelEngine: AnyObject {
    var transportEvidence: TunnelTransportEvidence { get }
    func start(completion: @escaping (Error?) -> Void)
    func stop(completion: @escaping () -> Void)
    func counters(completion: @escaping (String?) -> Void)
    func sleep()
    func wake()
}

extension PacketTunnelEngine {
    var transportEvidence: TunnelTransportEvidence { .unknown }
    func counters(completion: @escaping (String?) -> Void) { completion(nil) }
    func sleep() {}
    func wake() {}
}

final class AmneziaPacketTunnelEngine: PacketTunnelEngine {
    private let adapter: WireGuardAdapter
    private let configuration: WireGuardKit.TunnelConfiguration
    init(provider: NEPacketTunnelProvider, data: Data) throws {
        _ = try ProfileConfiguration.parse(data)
        guard let text = String(data: data, encoding: .utf8) else { throw ProfileError.invalidFile }
        configuration = try WireGuardKit.TunnelConfiguration(fromWgQuickConfig: text)
        adapter = WireGuardAdapter(with: provider) { _, _ in }
    }
    func start(completion: @escaping (Error?) -> Void) {
        adapter.start(tunnelConfiguration: configuration) { error in completion(error) }
    }
    func stop(completion: @escaping () -> Void) { adapter.stop { _ in completion() } }
    func counters(completion: @escaping (String?) -> Void) { adapter.getRuntimeConfiguration(completionHandler: completion) }
}
