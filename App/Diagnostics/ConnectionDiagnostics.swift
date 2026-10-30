import Foundation
import OSLog
import UndercoreMacCore

/// All mutable report state and disk I/O live on this serial queue, never on UI.
final class ConnectionDiagnostics: @unchecked Sendable {
    static let shared = ConnectionDiagnostics()
    private let queue = DispatchQueue(label: "ru.undercore.diagnostics", qos: .utility)
    private let logger = Logger(subsystem: "ru.undercore.macos", category: "Connection")
    private let archive: DiagnosticArchive
    private var recorder = DiagnosticSessionRecorder()

    private init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        archive = DiagnosticArchive(directory: base.appendingPathComponent("Undercore/Diagnostics", isDirectory: true))
        queue.async { [self] in try? archive.recoverInterrupted() }
    }
    func receive(_ event: VPNDiagnosticEvent) {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        #if arch(arm64)
        let architecture = "arm64"
        #else
        let architecture = "x86_64"
        #endif
        let context = ConnectionDiagnosticReport.Context(
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0",
            build: Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0",
            systemVersion: "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)", architecture: architecture)
        queue.async { [self] in
            for report in recorder.receive(event, context: context) {
                if let line = report.events.last?.value, !ConnectionDiagnosticReport.isSample(line) {
                    logger.info("\(line, privacy: .public)")
                }
                do { try archive.save(report, now: event.time) }
                catch { logger.error("diagnostic_write_failed") }
            }
        }
    }
    func export() async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [self] in
                do { continuation.resume(returning: try archive.export(keeping: recorder.report?.id)) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }
}
