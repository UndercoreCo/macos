import Foundation
import NetworkExtension
import Network
import UndercoreMacCore
import WireGuardKit

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var engine: PacketTunnelEngine?
    private let queue = DispatchQueue(label: "ru.undercore.tunnel.health")
    private lazy var reachability = TunnelReachability(queue: queue)
    private var runID = UUID()
    private var checkID = UUID()
    private var generation = UUID()
    private var active = false
    private var starting = false
    private var lifecycleGeneration = UUID()
    private var pathMonitor: NWPathMonitor?
    private var pathSignature: String?
    private var networkAvailable: Bool?
    private var sleeping = false
    private var policy = TunnelHealthPolicy()
    private var codes: [VPNDiagnosticCode] = [.health(.checking)]
    private var nextCheck: DispatchWorkItem?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let data = options?["configuration"] as? Data,
              let id = options?["runID"] as? String, let run = UUID(uuidString: id) else {
            completionHandler(NSError(domain: "UndercoreTunnel", code: 1)); return
        }
        do {
            let engine: PacketTunnelEngine
            switch try VPNTransportConfiguration.parse(data) {
            case .amneziaWG(let bytes): engine = try AmneziaPacketTunnelEngine(provider: self, data: bytes)
            case .trustTunnel(let configuration):
                #if TRUSTTUNNEL_EXPERIMENTAL
                engine = TrustTunnelEngine(provider: self, configuration: configuration, queue: queue)
                #else
                throw ClientError.unsupportedConfiguration
                #endif
            }
            queue.async {
                guard !self.active, !self.starting else { completionHandler(NSError(domain: "UndercoreTunnel", code: 4)); return }
                self.starting = true
                self.lifecycleGeneration = UUID()
                let token = self.lifecycleGeneration
                self.engine = engine
                engine.start { error in
                    self.queue.async {
                        guard self.lifecycleGeneration == token else { completionHandler(NSError(domain: "UndercoreTunnel", code: 5)); return }
                        self.starting = false
                        guard error == nil else { completionHandler(NSError(domain: "UndercoreTunnel", code: 2)); return }
                        self.runID = run; self.active = true; self.sleeping = false
                        self.policy = TunnelHealthPolicy()
                        self.monitorPath()
                        completionHandler(nil)
                        self.startCheck(id: UUID())
                    }
                }
            }
        } catch { completionHandler(NSError(domain: "UndercoreTunnel", code: 1)) }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.async {
            self.lifecycleGeneration = UUID(); self.starting = false
            self.active = false; self.invalidateCheck()
            self.pathMonitor?.cancel(); self.pathMonitor = nil; self.pathSignature = nil
            if let engine = self.engine {
                self.engine = nil; engine.stop(completion: completionHandler)
            } else { completionHandler() }
        }
    }
    override func sleep(completionHandler: @escaping () -> Void) {
        queue.async { self.sleeping = true; self.engine?.sleep(); self.invalidateCheck(); self.codes = [.health(.checking)]; completionHandler() }
    }
    override func wake() {
        queue.async { self.sleeping = false; self.engine?.wake(); self.policy = TunnelHealthPolicy(); self.startCheck(id: UUID()) }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let request = TunnelStatusRequest.decode(messageData) else { completionHandler?(nil); return }
        queue.async {
            guard self.active else { completionHandler?(nil); return }
            if request.command == .check { self.policy = TunnelHealthPolicy(); self.startCheck(id: request.id) }
            let token = self.generation
            self.readCounters { raw in
                let counter = raw.flatMap(TunnelCounters.parse)
                self.queue.async {
                    guard self.active, token == self.generation else { completionHandler?(nil); return }
                    var codes = self.codes
                    if let counter { codes.append(counter.diagnostic) }
                    let reply = TunnelStatusReply(requestID: request.id, runID: self.runID, checkID: self.checkID, codes: codes)
                    completionHandler?(try? JSONEncoder().encode(reply))
                }
            }
        }
    }

    private func readCounters(completion: @escaping (String?) -> Void) {
        guard let engine else { completion(nil); return }
        engine.counters(completion: completion)
    }

    private func monitorPath() {
        pathMonitor?.cancel(); pathSignature = nil
        let monitor = NWPathMonitor()
        pathMonitor = monitor
        let lifecycle = lifecycleGeneration
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self, self.lifecycleGeneration == lifecycle, self.active else { return }
            self.networkAvailable = path.status == .satisfied
            let names = path.availableInterfaces.filter { $0.type != .other }.map(\.name).sorted().joined(separator: ",")
            let signature = "\(path.status):\(names)"
            defer { self.pathSignature = signature }
            guard let previous = self.pathSignature, signature != previous, !self.sleeping else { return }
            self.invalidateCheck(); self.policy = TunnelHealthPolicy(); self.codes = [.health(.checking)]
            let work = DispatchWorkItem { [weak self] in self?.startCheck(id: UUID()) }
            self.nextCheck = work
            self.queue.asyncAfter(deadline: .now() + 2, execute: work)
        }
        monitor.start(queue: queue)
    }

    private func scheduleCheck(after delay: Double) {
        let work = DispatchWorkItem { [weak self] in self?.startCheck(id: UUID()) }
        nextCheck = work
        queue.asyncAfter(deadline: .now() + delay, execute: work)
    }
    private func invalidateCheck() {
        generation = UUID(); nextCheck?.cancel(); nextCheck = nil; reachability.cancel()
    }
    private func startCheck(id: UUID) {
        invalidateCheck()
        guard active, !sleeping else { return }
        checkID = id; codes = [.health(.checking)]
        let token = generation
        readCounters { raw in
            let before = raw.flatMap(TunnelCounters.parse)
            self.queue.async {
                guard self.active, !self.sleeping, token == self.generation else { return }
                self.reachability.check(provider: self) { result in
                    self.readCounters { raw in
                        let after = raw.flatMap(TunnelCounters.parse)
                        self.queue.async {
                            guard self.active, !self.sleeping, token == self.generation else { return }
                            let observation = TunnelHealthObservation(
                                tunnelIP: result.tunnelIP, tunnelName: result.tunnelName,
                                dnsFailed: result.dnsFailed, directInternet: result.directInternet,
                                networkAvailable: self.networkAvailable, before: before, after: after,
                                wallTime: Date().timeIntervalSince1970,
                                monotonicTime: ProcessInfo.processInfo.systemUptime,
                                transportEvidence: self.engine?.transportEvidence ?? .unknown)
                            let health = self.policy.observe(observation)
                            var codes = result.codes
                            if let after {
                                codes.append(.probe(.handshake_fresh, observation.freshHandshake ? .ok : .failed))
                                if observation.countersComparable, let before {
                                    codes.append(.probe(.rx_progress, after.received > before.received ? .ok : .failed))
                                    codes.append(.probe(.tx_progress, after.sent > before.sent ? .ok : .failed))
                                }
                            }
                            self.codes = codes + [.health(health)]
                            // Keep the tunnel running; the interchangeable backend/coordinator
                            // decides bounded recovery from the explicit health diagnosis.
                            self.scheduleCheck(after: health == .ok ? 60 : 10)
                        }
                    }
                }
            }
        }
    }
}
