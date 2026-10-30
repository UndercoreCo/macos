import AppKit
import Combine
import Network
import UndercoreMacCore

@MainActor
final class TunnelController: ObservableObject {
    private static let profileKey = "connectionProfile"
    let account = AccountStore()
    @Published var appUpdateInProgress = false
    var blocksAppUpdate: Bool { busy || active || account.busy || recovery.recovering }
    @Published private(set) var profile: ConnectionProfile?
    @Published private(set) var status: VPNState = .disconnected
    @Published private(set) var busy = true
    @Published var message: String?
    private var powerObservers = Set<AnyCancellable>()
    private let backend: any VPNBackend
    private lazy var recovery = VPNRecoveryCoordinator(backend: backend)
    private let networkMonitor = NWPathMonitor()
    private var recoveryFailureMessage: String?
    private var managedConfiguration: ManagedConfigurationRecovery?
    private var diagnosticSessionID: UUID?
    private var networkSignature: String?

    init(backend: (any VPNBackend)? = nil) {
        self.backend = backend ?? BackendFactory.make()
        self.backend.onDiagnosticEvent = { [weak self] event in
            if case .began = event.kind { self?.diagnosticSessionID = event.sessionID }
            if case .ended = event.kind, self?.diagnosticSessionID == event.sessionID { self?.diagnosticSessionID = nil }
            self?.recovery.observe(event)
            ConnectionDiagnostics.shared.receive(event)
        }
        recovery.onDiagnosticEvent = { ConnectionDiagnostics.shared.receive($0) }
        self.backend.onStateChange = { [weak self] state, message in
            guard let self else { return }
            if self.recovery.recovering && state != .disconnecting && state != .disconnected { return }
            self.status = state
            if state == .disconnected, let message, !message.isEmpty { self.message = message }
            else if state == .disconnected, let failure = self.recoveryFailureMessage { self.message = failure }
            else if let message { self.message = message.isEmpty ? nil : message }
        }
        self.backend.onRecoveryEvent = { [weak self] event in self?.recovery.receive(event) }
        recovery.onChange = { [weak self] message in
            guard let self, let message else { return }
            self.status = .reasserting
            self.message = message
        }
        recovery.onPreparationFailure = { [weak self] error in
            guard let self else { return }
            self.recoveryFailureMessage = AccountStore.describe(error)
            self.message = self.recoveryFailureMessage
            Task { await self.backend.disconnect() }
        }
        recovery.onReconnectSucceeded = { [weak self] in self?.managedConfiguration?.didReconnect() }
        recovery.onExhausted = { [weak self] in
            guard let self else { return }
            self.recoveryFailureMessage = "Не удалось восстановить VPN. Проверьте сеть и подключитесь ещё раз."
            Task { await self.backend.disconnect() }
        }
        networkMonitor.pathUpdateHandler = { [weak self] path in
            let available = path.status == .satisfied
            let names = path.availableInterfaces.filter { $0.type != .other }.map(\.name).sorted().joined(separator: ",")
            let signature = "\(path.status):\(names)"
            Task { @MainActor [weak self] in
                guard let self else { return }
                if let previous = self.networkSignature, previous != signature { self.recovery.networkChanged() }
                self.networkSignature = signature
                self.recovery.networkAvailable = available
            }
        }
        networkMonitor.start(queue: DispatchQueue(label: "ru.undercore.network-path"))

        if let saved = UserDefaults.standard.data(forKey: Self.profileKey),
           let restored = try? JSONDecoder().decode(ConnectionProfile.self, from: saved),
           restored.accountConnection != nil {
            profile = restored
        } else {
            // Imported profiles are no longer selectable. Keep the account session
            // and device UUID so the next connection reuses the existing slot.
            UserDefaults.standard.removeObject(forKey: Self.profileKey)
        }
        let powerCenter = NSWorkspace.shared.notificationCenter
        powerCenter.publisher(for: NSWorkspace.willSleepNotification)
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.handlePowerEvent(.willSleep) }
            .store(in: &powerObservers)
        powerCenter.publisher(for: NSWorkspace.didWakeNotification)
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.handlePowerEvent(.didWake) }
            .store(in: &powerObservers)
        Task { await restore() }
    }

    deinit { networkMonitor.cancel() }

    private func handlePowerEvent(_ event: VPNSystemEvent) {
        recovery.setSleeping(event == .willSleep)
        backend.handleSystemEvent(event)
    }

    var requiresSystemExtensionApproval: Bool { canCancelPending && backend.requiresSystemExtensionApproval }
    var canCancelPending: Bool { busy && status == .connecting && backend.canCancelPending }
    func cancelConnection() { recovery.cancel(); Task { await backend.disconnect() } }

    var active: Bool { [.connected, .unverified, .checking, .degraded, .connecting, .reasserting, .disconnecting].contains(status) }
    var statusText: String {
        switch status {
        case .connected: return "VPN включён"
        case .unverified: return "VPN подключён · доступ не проверен"
        case .checking: return "VPN подключён · проверяем интернет"
        case .degraded: return "VPN · проблема подключения"
        case .connecting: return "Подключаемся…"
        case .reasserting: return "Восстанавливаем соединение…"
        case .disconnecting: return "Отключаемся…"
        case .disconnected: return busy ? "Подготавливаем подключение…" : "VPN выключен"
        }
    }

    var statusSymbol: String {
        switch status {
        case .connected: return "checkmark.shield"
        case .degraded: return "exclamationmark.shield"
        case .disconnected: return "xmark.shield"
        default: return "shield.lefthalf.filled"
        }
    }
    /// The only connect action in the UI also prepares the first account binding.
    func connectFromMainScreen() async {
        guard !appUpdateInProgress, !busy, !active, !account.busy else { return }
        if profile != nil {
            await connect()
            return
        }
        guard let user = account.account, user.isEmailVerified else { return }
        message = nil
        if account.automaticConnectionAvailable {
            guard let connection = await account.prepareAutomaticConnection() else {
                message = account.message
                return
            }
            await connectAccount(connection, ownerID: user.id)
        } else if let connection = account.selected {
            await connectAccount(connection, ownerID: user.id)
        }
    }

    func connect() async {
        guard !appUpdateInProgress, !busy, !active, !account.busy, let profile,
              let binding = profile.accountConnection else { return }
        busy = true
        message = nil
        recoveryFailureMessage = nil
        managedConfiguration = nil
        recovery.configurationForRecovery = nil
        recovery.start()
        defer { busy = false }
        do {
            let configuration = try await account.configuration(for: binding)
            let data = configuration.data
            configureManagedRecovery(configuration, profile: profile, binding: binding)
            _ = try VPNTransportConfiguration.parse(data)
            try await backend.connect(configuration: data, profile: profile)
            message = nil
        } catch is CancellationError { recovery.cancel(); message = nil }
        catch let error as Failure { recovery.cancel(); message = error.localizedDescription }
        catch let error as ProfileError { recovery.cancel(); message = error.localizedDescription }
        catch let error as ClientError { recovery.cancel(); message = error.localizedDescription }
        catch { recovery.cancel(); message = Failure.start.localizedDescription }
    }

    func connectAccount(_ connection: AccountConnection, ownerID: Int) async {
        guard !appUpdateInProgress, !busy, !active, !account.busy, account.isAvailable(connection),
              account.account?.id == ownerID else { return }
        let selected = ConnectionProfile(name: connection.displayName,
            accountConnection: .init(accountID: ownerID, configurationID: connection.id))
        guard let metadata = try? JSONEncoder().encode(selected) else { return }
        UserDefaults.standard.set(metadata, forKey: Self.profileKey)
        profile = selected
        await connect()
    }

    func selectAutomaticTransport(_ transport: VPNTransport) {
        guard !appUpdateInProgress, !busy, !active, !account.busy else { return }
        account.automaticTransport = transport
        clearSelectedProfile()
    }

    func useAccountProfile() {
        guard !appUpdateInProgress, !busy, !active, !account.busy, let user = account.account else { return }
        // Keep a valid binding; first setup reuses the persisted device UUID.
        if profile?.accountConnection?.accountID == user.id { return }
        clearSelectedProfile()
    }

    func accountDidLogout() {
        guard !busy, !active, profile?.accountConnection != nil else { return }
        // Signing out also clears the local account binding.
        clearSelectedProfile()
    }

    private func clearSelectedProfile() {
        UserDefaults.standard.removeObject(forKey: Self.profileKey)
        profile = nil
        message = nil
    }

    func disconnect() {
        guard !busy else { return }
        recovery.cancel()
        managedConfiguration = nil
        recovery.configurationForRecovery = nil
        recoveryFailureMessage = nil
        Task { await backend.disconnect() }
    }

    func confirmRemoval() async {
        guard !busy, !active, let profile else { return }
        // Wait for the action menu to close. A standalone AppKit alert owns its
        // event loop, so dismissing MenuBarExtra cannot swallow the action.
        await Task.yield()
        let alert = NSAlert()
        alert.messageText = "Удалить подключение с этого Mac?"
        alert.informativeText = "Доступ в личном кабинете сохранится"
        alert.alertStyle = .warning
        let cancel = alert.addButton(withTitle: "Отмена")
        cancel.keyEquivalent = "\r"
        let remove = alert.addButton(withTitle: "Удалить")
        remove.hasDestructiveAction = true
        remove.keyEquivalent = ""
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertSecondButtonReturn,
              self.profile?.id == profile.id else { return }
        await self.remove()
    }

    func remove() async {
        guard !busy, !active, profile != nil else { return }
        busy = true
        defer { busy = false }
        do {
            try await backend.remove()
            UserDefaults.standard.removeObject(forKey: Self.profileKey)
            self.profile = nil
            status = .disconnected
            message = nil
        } catch { message = "Не удалось удалить подключение. Попробуйте ещё раз." }
    }

    private func configureManagedRecovery(_ configuration: ManagedConfiguration,
                                          profile: ConnectionProfile,
                                          binding: ConnectionProfile.AccountBinding) {
        let updates = ManagedConfigurationRecovery(current: configuration)
        managedConfiguration = updates
        updates.onOutcome = { [weak self] outcome in
            guard let self, let sessionID = self.diagnosticSessionID else { return }
            ConnectionDiagnostics.shared.receive(.init(sessionID: sessionID,
                kind: .code(.configurationUpdate(outcome))))
        }
        guard backend.supportsConfigurationUpdates else { return }
        recovery.configurationForRecovery = { [weak self, weak updates] in
            guard let self, let updates, self.profile?.id == profile.id else { throw CancellationError() }
            return try await updates.refresh(attempt: self.recovery.attempt, allowAlternative: self.recovery.canRequestAlternative, recover: { [weak self] revision in
                guard let self, self.profile?.id == profile.id else { throw CancellationError() }
                return try await self.account.configuration(for: binding, recoveryRevision: revision)
            }) { [weak self] in
                guard let self, self.profile?.id == profile.id else { throw CancellationError() }
                return try await self.account.configuration(for: binding)
            }
        }
    }

    private func restore() async {
        do { try await backend.restore() }
        catch { message = Failure.preferences.localizedDescription }
        busy = false
        // An account-selected first connection must be available after relaunch.
        if profile == nil, account.canRestore { await account.refresh() }
    }
}
