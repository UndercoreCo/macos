import AppKit
import SwiftUI

struct ConnectionView: View {
    @Environment(\.openWindow) private var openWindow
    @ObservedObject var tunnel: TunnelController
    @ObservedObject var account: AccountStore
    @State private var presentation = MenuBarPresentation()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Spacer()
                Menu {
                    Button("Аккаунт и настройки", systemImage: "person.crop.circle") { showAccount() }
                        .keyboardShortcut(",", modifiers: .command)
                    if tunnel.profile != nil {
                        Button("Удалить подключение", systemImage: "trash", role: .destructive) {
                            presentation.perform { await tunnel.confirmRemoval() }
                        }.disabled(tunnel.appUpdateInProgress || tunnel.active || tunnel.busy || account.busy)
                    }
                    Divider()
                    Button("Выход из Undercore") { NSApp.terminate(nil) }
                        .disabled(tunnel.appUpdateInProgress || tunnel.active || tunnel.busy || account.busy)
                } label: {
                    Image(systemName: "gearshape")
                        .font(.system(size: 16))
                        .frame(width: 24, height: 24)
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .help("Управление приложением")
                .fixedSize()
                .accessibilityLabel("Действия")
            }
            VStack(spacing: 20) {
                Image(systemName: shieldSymbol)
                    .font(.system(size: 76, weight: .light))
                    .symbolRenderingMode(.monochrome)
                    .foregroundStyle(shieldColor)
                    .frame(maxWidth: .infinity)
                    .frame(height: 100)
                    .accessibilityHidden(true)

                VStack(spacing: 8) {
                    Text(tunnel.profile?.name ?? (canSetUpConnection ? "Подключение" : "Добавьте подключение"))
                        .font(.title2)
                        .foregroundStyle(.primary)
                    Text(connectionStatusText)
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity)

                if tunnel.profile == nil, !account.automaticConnectionAvailable, !account.connections.isEmpty || account.hasMore {
                    Picker("Подключение", selection: $account.selectedID) {
                        Text("Выберите подключение").tag(nil as String?)
                        ForEach(account.connections) { item in
                            Text(item.displayName).tag(Optional(item.id)).disabled(!account.isAvailable(item))
                        }
                    }
                    .disabled(tunnel.appUpdateInProgress || tunnel.active || tunnel.busy || account.busy)
                    if account.hasMore {
                        Button("Загрузить ещё") { Task { await account.loadMore() } }
                            .disabled(account.busy || tunnel.busy || tunnel.active)
                    }
                }
                if tunnel.requiresSystemExtensionApproval {
                    approvalActions
                } else if tunnel.profile != nil || canSetUpConnection {
                    connectionButton
                } else {
                    setupButtons
                }
            }
        }
        .padding(20)
        .frame(width: 340)
        .fixedSize(horizontal: false, vertical: true)
        .background(MenuBarWindowReader(presentation: presentation))
    }
    private var approvalActions: some View {
        VStack(spacing: 12) {
            Text(SystemExtensionSettings.instructions)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity)
            Button {
                presentation.perform { SystemExtensionSettings.open() }
            } label: {
                setupButtonLabel("Открыть настройки", symbol: "gearshape")
            }
            .buttonStyle(.borderedProminent)
            Button { tunnel.cancelConnection() } label: {
                setupButtonLabel("Отменить", symbol: "xmark")
            }
            .buttonStyle(.bordered)
        }
        .controlSize(.large)
    }

    private var setupButtons: some View {
        VStack(spacing: 12) {
            Button { showAccount() } label: {
                setupButtonLabel(account.account == nil ? "Войти в аккаунт" : "Аккаунт и настройки", symbol: "person.crop.circle")
            }
            .buttonStyle(.borderedProminent)

        }
        .controlSize(.large)
    }

    private func setupButtonLabel(_ title: String, symbol: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: symbol)
                .font(.system(size: 16))
                .frame(width: 20, height: 20)
            Text(title).font(.body)
        }
        .frame(maxWidth: .infinity, minHeight: 32)
    }

    private var isTransitioning: Bool {
        tunnel.busy || account.busy || [.connecting, .checking, .reasserting, .disconnecting].contains(tunnel.status)
    }

    private var shieldSymbol: String {
        switch tunnel.status {
        case .connected: "checkmark.shield.fill"
        case .degraded: "exclamationmark.shield.fill"
        default: "shield.lefthalf.filled"
        }
    }

    private var shieldColor: Color {
        switch tunnel.status {
        case .connected: .blue
        case .degraded: .orange
        default: Color(nsColor: .tertiaryLabelColor)
        }
    }

    private var connectionButtonTitle: String {
        if tunnel.canCancelPending { return "Отменить" }
        if tunnel.status == .disconnecting { return "Отключаемся…" }
        if tunnel.busy || account.busy { return "Подождите…" }
        return tunnel.active ? "Отключиться" : "Подключиться"
    }

    private var connectionButton: some View {
        Button {
            if tunnel.canCancelPending { tunnel.cancelConnection() }
            else if tunnel.active { tunnel.disconnect() }
            else { Task { await tunnel.connectFromMainScreen() } }
        } label: {
            HStack(spacing: 10) {
                // Reserve the spinner's space so neither the label nor the shield moves.
                Group {
                    if isTransitioning {
                        ProgressView().controlSize(.small)
                    } else {
                        Color.clear
                    }
                }
                .frame(width: 16, height: 16)
                .accessibilityHidden(true)
                Text(connectionButtonTitle)
                Color.clear.frame(width: 16, height: 16)
            }
            .frame(maxWidth: .infinity, minHeight: 32)
        }
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
        .disabled(tunnel.appUpdateInProgress || (tunnel.busy && !tunnel.canCancelPending) || (account.busy && !tunnel.active) || tunnel.status == .disconnecting
            || (tunnel.profile == nil && !account.automaticConnectionAvailable && account.selected == nil))
    }

    private var canSetUpConnection: Bool {
        account.account?.isEmailVerified == true
            && (account.automaticConnectionAvailable || !account.connections.isEmpty)
    }

    // Progress and errors belong only to the connection screen.
    private var connectionStatusText: String {
        if tunnel.profile == nil, account.busy { return "Подготавливаем подключение…" }
        if let statusMessage { return statusMessage }
        if tunnel.profile != nil || canSetUpConnection { return tunnel.statusText }
        return account.account == nil ? "Войдите в аккаунт, чтобы подключиться"
            : "Проверьте доступ к подписке в личном кабинете"
    }

    private var statusMessage: String? {
        guard let message = tunnel.message?.trimmingCharacters(in: .whitespacesAndNewlines),
              !message.isEmpty else { return nil }
        return message
    }

    private func showAccount() {
        presentation.perform { openWindow(id: "account") }
    }
}
