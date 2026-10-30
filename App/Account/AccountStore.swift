import Foundation
import UndercoreMacCore

@MainActor final class AccountStore: ObservableObject {
    @Published private(set) var account: Account?
    @Published private(set) var connections: [AccountConnection] = []
    @Published private(set) var experimentalTrustTunnelAvailable = false
    @Published var automaticTransport: VPNTransport = .amneziawg {
        didSet { UserDefaults.standard.set(automaticTransport.rawValue, forKey: "experimentalAutomaticTransport") }
    }
    @Published private(set) var automaticConnectionAvailable = false
    @Published private(set) var busy = false
    @Published private(set) var message: String?
    @Published var selectedID: String?
    @Published private(set) var lastPage = 1
    private var page = 0
    private var client: AccountAPI?
    var hasMore: Bool { page > 0 && page < lastPage }
    var canRestore: Bool { client?.hasSession == true }
    var selected: AccountConnection? { connections.first { $0.id == selectedID && isAvailable($0) } }

    private static var transports: Set<VPNTransport> {
        #if TRUSTTUNNEL_EXPERIMENTAL
        [.amneziawg, .trusttunnel]
        #else
        [.amneziawg]
        #endif
    }
    func isAvailable(_ connection: AccountConnection) -> Bool { connection.isAvailable(for: Self.transports) }

    init() {
        if let saved = UserDefaults.standard.string(forKey: "experimentalAutomaticTransport"),
           let transport = VPNTransport(rawValue: saved), Self.transports.contains(transport) {
            automaticTransport = transport
        }
        do {
            client = try AccountAPI(store: KeychainSessionStore(service: "ru.undercore.macos.account"), supportedTransports: Self.transports)
            client?.onSessionInvalidated = { [weak self] in
                self?.experimentalTrustTunnelAvailable = false
                self?.automaticTransport = .amneziawg
                self?.automaticConnectionAvailable = false
                self?.account = nil
                self?.connections = []
                self?.selectedID = nil
                self?.page = 0
                self?.lastPage = 1
            }
        } catch { message = Self.describe(error) }
    }
    func login(email: String, password: String) async {
        guard !busy, let client else { return }
        guard !email.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !password.isEmpty else {
            message = "Введите почту и пароль."; return
        }
        busy = true; message = nil
        defer { busy = false }
        do {
            account = try await client.login(email: email, password: password)
            try await loadPage(1)
        } catch { handle(error) }
    }
    func refresh() async {
        guard !busy, let client else { return }
        busy = true; message = nil
        connections = []; page = 0; lastPage = 1
        defer { busy = false }
        do {
            account = try await client.currentAccount()
            try await loadPage(1)
        } catch { handle(error) }
    }
    func loadMore() async {
        guard !busy, hasMore else { return }
        busy = true; message = nil
        defer { busy = false }
        do { try await loadPage(page + 1) } catch { handle(error) }
    }
    func configuration(for binding: ConnectionProfile.AccountBinding, recoveryRevision: Int? = nil) async throws -> ManagedConfiguration {
        guard let client else { throw ClientError.expiredSession }
        guard !busy else { throw URLError(.resourceUnavailable) }
        busy = true
        defer { busy = false }
        do {
            if let recoveryRevision {
                return try await client.recoverConnection(id: binding.configurationID, ownerID: binding.accountID, expectedRevision: recoveryRevision)
            }
            return try await client.managedConfiguration(id: binding.configurationID, ownerID: binding.accountID)
        }
        catch { handle(error); throw error }
    }
    func prepareAutomaticConnection() async -> AccountConnection? {
        guard !busy, automaticConnectionAvailable, let client, let account else { return nil }
        let requestedTransport = automaticTransport
        guard Self.transports.contains(requestedTransport), requestedTransport != .trusttunnel || experimentalTrustTunnelAvailable else {
            message = "Тестовое подключение недоступно для этого аккаунта."; return nil
        }
        busy = true; message = "Подготавливаем подключение…"
        defer { busy = false }
        // Persist before the request. A timeout/restart must retry the same device.
        let storageKey = "automaticDeviceKey.\(account.id)" + (requestedTransport == .trusttunnel ? ".trusttunnel" : "")
        let deviceKey: UUID
        if let saved = UserDefaults.standard.string(forKey: storageKey) {
            guard let parsed = UUID(uuidString: saved) else {
                message = "Не удалось прочитать идентификатор этого Mac."; return nil
            }
            deviceKey = parsed
        } else {
            deviceKey = UUID()
            UserDefaults.standard.set(deviceKey.uuidString, forKey: storageKey)
        }
        do {
            var connection = try await client.connectDevice(key: deviceKey,
                name: (Host.current().localizedName ?? "Mac") + (requestedTransport == .trusttunnel ? " · TrustTunnel" : ""), ownerID: account.id, transport: requestedTransport)
            for _ in 0..<15 {
                if isAvailable(connection) {
                    if !connections.contains(where: { $0.id == connection.id }) { connections.append(connection) }
                    selectedID = connection.id; message = nil
                    return connection
                }
                guard connection.state == "provisioning" else { throw ClientError.unavailable }
                try await Task.sleep(for: .seconds(2))
                connection = try await client.connection(id: connection.id)
            }
            message = "Подключение ещё готовится. Попробуйте снова — дополнительное место занято не будет."
        } catch { handle(error) }
        return nil
    }

    func logout() async {
        guard !busy, let client else { return }
        busy = true; message = nil
        defer { busy = false }
        do { try await client.logout() }
        catch {
            if error as? ClientError == .insecureStorage {
                message = "Не удалось удалить сохранённую сессию из связки ключей. Разблокируйте Mac и повторите выход."
            } else if client.hasSession { message = Self.describe(error) }
            else { message = "Вы вышли на этом Mac. Не удалось подтвердить завершение сессии на сервере." }
        }
    }
    private func loadPage(_ number: Int) async throws {
        guard let account, account.isEmailVerified else { throw ClientError.unverified }
        guard let client else { throw ClientError.unavailable }
        let result = try await client.page(number)
        if number == 1 {
            automaticConnectionAvailable = result.automaticConnectionAvailable == true
            experimentalTrustTunnelAvailable = Self.transports.contains(.trusttunnel) && result.experimentalTrustTunnelAvailable == true
        }
        if number == 1 { connections = [] }
        let known = Set(connections.map(\.id))
        connections += result.connections.filter { !known.contains($0.id) }
        page = number; lastPage = result.pagination.lastPage
        if !connections.contains(where: { $0.id == selectedID && isAvailable($0) }) { selectedID = nil }
        let available = connections.filter { isAvailable($0) }
        if selectedID == nil, available.count == 1, !hasMore { selectedID = available[0].id }
    }
    private func handle(_ error: Error) {
        if error as? ClientError == .expiredSession { account = nil; connections = []; selectedID = nil }
        message = Self.describe(error)
    }
    static func describe(_ error: Error) -> String {
        if let error = error as? ClientError { return error.localizedDescription }
        if let error = error as? ProfileError { return error.localizedDescription }
        if error is CancellationError { return "Действие отменено." }
        return "Не удалось связаться с Undercore. Проверьте интернет и попробуйте снова."
    }
}
