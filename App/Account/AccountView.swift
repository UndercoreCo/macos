import AppKit
import ServiceManagement
import SwiftUI
import UndercoreMacCore

struct AccountView: View {
    @ObservedObject var account: AccountStore
    @ObservedObject var tunnel: TunnelController
    @ObservedObject var updates: AppUpdateController
    @State private var email = ""
    @State private var password = ""
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    @State private var notice: String?
    @FocusState private var focus: Field?
    private enum Field { case email, password }
    private var blocked: Bool { account.busy || tunnel.busy || tunnel.active || tunnel.appUpdateInProgress }

    var body: some View {
        Form {
            Section("Аккаунт") {
                if let user = account.account {
                    LabeledContent("Почта") { Text(user.email).textSelection(.enabled) }
                    if !user.isEmailVerified {
                        Link("Подтвердить почту в личном кабинете", destination: AccountEndpoints.website)
                    }
                    Button("Выйти") {
                        Task {
                            await account.logout()
                            if !account.canRestore { tunnel.accountDidLogout() }
                            showAccountError()
                        }
                    }
                    .disabled(blocked)
                    .help(tunnel.active ? "Сначала отключите VPN на главном экране" : "Выйти из аккаунта на этом Mac")
                } else {
                    TextField("Почта", text: $email)
                        .textContentType(.username)
                        .focused($focus, equals: .email)
                        .onSubmit { focus = .password }
                        .disabled(blocked)
                    SecureField("Пароль", text: $password)
                        .textContentType(.password)
                        .focused($focus, equals: .password)
                        .onSubmit { signIn() }
                        .disabled(blocked)
                    HStack {
                        Button("Войти", action: signIn)
                            .buttonStyle(.borderedProminent)
                            .disabled(blocked || email.isEmpty || password.isEmpty)
                        if account.busy { ProgressView().controlSize(.small) }
                        Spacer()
                        Link("Забыли пароль?", destination: AccountEndpoints.forgotPassword)
                    }
                    Link("Создать аккаунт", destination: AccountEndpoints.register)
                    if account.canRestore {
                        Button("Восстановить вход") {
                            Task {
                                await account.refresh()
                                if account.account != nil { tunnel.useAccountProfile() }
                                showAccountError()
                            }
                        }
                        .disabled(blocked)
                    }
                }
                Link(destination: AccountEndpoints.website) {
                    Label("Личный кабинет", systemImage: "arrow.up.right.square")
                }
            }
            #if TRUSTTUNNEL_EXPERIMENTAL
            if account.experimentalTrustTunnelAvailable {
                Section("Тестирование") {
                    Picker("Подключение", selection: Binding(
                        get: { account.automaticTransport },
                        set: { tunnel.selectAutomaticTransport($0) }
                    )) {
                        Text("AmneziaWG").tag(VPNTransport.amneziawg)
                        Text("TrustTunnel").tag(VPNTransport.trusttunnel)
                    }.disabled(blocked)
                    Text("TrustTunnel использует отдельное место в подписке. Подключение запускается на главном экране.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            #endif
            Section("Приложение") {
                Toggle("Открывать при входе в macOS", isOn: Binding(
                    get: { launchAtLogin }, set: setLaunchAtLogin
                ))
                LabeledContent("Версия", value: version)
                Button("Проверить обновления…", systemImage: "arrow.triangle.2.circlepath") {
                    updates.checkForUpdates()
                }
                .disabled(!updates.canCheck)
                if updates.enabled {
                    Toggle("Проверять обновления автоматически", isOn: Binding(
                        get: { updates.automaticChecks }, set: updates.setAutomaticChecks
                    ))
                    LabeledContent("Канал обновлений", value: "Тестовый")
                }
                if updates.installationPending {
                    Button("Установить обновление и перезапустить") { updates.installPendingUpdate() }
                        .disabled(tunnel.blocksAppUpdate)
                }
                if let message = updates.message {
                    Text(message).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Button("Сохранить диагностику…", systemImage: "square.and.arrow.up") {
                    Task { notice = await DiagnosticExporter.save() }
                }
                Link(destination: URL(string: "https://docs.undercore.ru")!) {
                    Label("Помощь", systemImage: "questionmark.circle")
                }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 460, minHeight: 480)
        .alert("Undercore", isPresented: Binding(
            get: { notice != nil }, set: { if !$0 { notice = nil } }
        )) { Button("OK") { notice = nil } } message: { Text(notice ?? "") }
        .task {
            if account.canRestore, !tunnel.busy, !account.busy {
                await account.refresh()
                showAccountError()
            }
        }
        .onDisappear { password = "" }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            launchAtLogin = SMAppService.mainApp.status == .enabled
        }
    }

    private var version: String {
        let info = Bundle.main.infoDictionary ?? [:]
        let version = info["CFBundleShortVersionString"] as? String ?? "—"
        guard let build = info["CFBundleVersion"] as? String else { return version }
        return "\(version) (\(build))"
    }

    private func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
            if SMAppService.mainApp.status == .requiresApproval {
                notice = "Разрешите автозапуск в настройках объектов входа macOS."
            }
        } catch {
            notice = "Не удалось изменить автозапуск. Проверьте настройки объектов входа macOS."
        }
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    private func showAccountError() {
        if let message = account.message { notice = message }
    }

    private func signIn() {
        guard !blocked, !email.isEmpty, !password.isEmpty else { return }
        let submittedPassword = password
        password = ""
        Task {
            await account.login(email: email, password: submittedPassword)
            if account.account != nil { tunnel.useAccountProfile() }
            showAccountError()
        }
    }
}
