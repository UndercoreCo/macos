import AppKit
import Combine
import Sparkle
import UndercoreMacCore

/// Sparkle owns discovery, download, signature verification and replacement.
/// Undercore only controls when it is safe to terminate its VPN client.
@MainActor
final class AppUpdateController: NSObject, ObservableObject, SPUUpdaterDelegate {
    @Published private(set) var canCheck = false
    @Published private(set) var automaticChecks = false
    @Published private(set) var installationPending = false
    @Published private(set) var message: String?
    let enabled: Bool
    private let tunnel: TunnelController
    private let installation = UpdateInstallationGate()
    private var controller: SPUStandardUpdaterController!
    private var observations = Set<AnyCancellable>()

    init(tunnel: TunnelController) {
        self.tunnel = tunnel
        enabled = Bundle.main.object(forInfoDictionaryKey: "UndercoreUpdatesEnabled") as? String == "YES"
        super.init()
        UpdateApplicationDelegate.updates = self
        guard enabled else {
            message = "Обновления появятся после публикации тестового канала."
            return
        }
        controller = SPUStandardUpdaterController(startingUpdater: false, updaterDelegate: self, userDriverDelegate: nil)
        controller.updater.publisher(for: \.canCheckForUpdates)
            .sink { [weak self] in self?.canCheck = $0 }.store(in: &observations)
        controller.updater.publisher(for: \.automaticallyChecksForUpdates)
            .sink { [weak self] in self?.automaticChecks = $0 }.store(in: &observations)
        do { try controller.updater.start() }
        catch { message = "Не удалось включить проверку обновлений." }
    }

    func checkForUpdates() {
        guard enabled, canCheck else { return }
        NSApp.activate(ignoringOtherApps: true)
        controller.checkForUpdates(nil)
    }

    func setAutomaticChecks(_ enabled: Bool) {
        guard self.enabled else { return }
        controller.updater.automaticallyChecksForUpdates = enabled
    }

    func updater(_ updater: SPUUpdater, shouldPostponeRelaunchForUpdate item: SUAppcastItem,
                 untilInvokingBlock installHandler: @escaping () -> Void) -> Bool {
        if installation.postpone(if: tunnel.blocksAppUpdate, install: installHandler) {
            installationPending = true
            message = "Обновление готово. Отключите VPN и нажмите «Установить обновление и перезапустить»."
            return true
        }
        tunnel.appUpdateInProgress = true
        return false
    }

    func installPendingUpdate() {
        guard !tunnel.blocksAppUpdate, installation.hasPending else { return }
        tunnel.appUpdateInProgress = true
        installationPending = false
        message = "Устанавливаем обновление…"
        installation.resume(ifSafe: true)
    }

    // The final guard also covers Sparkle retries where postponement is not called.
    func mayTerminate() -> Bool {
        guard !tunnel.blocksAppUpdate else {
            message = "Сначала отключите VPN и дождитесь завершения текущей операции."
            return false
        }
        return true
    }

    func updater(_ updater: SPUUpdater, didAbortWithError error: Error) {
        installation.cancel()
        installationPending = false
        tunnel.appUpdateInProgress = false
        // Sparkle displays its own error. Never copy URLs or server bodies to diagnostics.
    }
}

@MainActor
final class UpdateApplicationDelegate: NSObject, NSApplicationDelegate {
    static weak var updates: AppUpdateController?
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        Self.updates?.mayTerminate() == false ? .terminateCancel : .terminateNow
    }
}
