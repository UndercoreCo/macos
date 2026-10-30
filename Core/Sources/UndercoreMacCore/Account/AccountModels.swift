import Foundation

public struct Account: Decodable, Equatable, Sendable {
    public let id: Int
    public let name: String
    public let email: String
    public let isEmailVerified: Bool
}
struct Envelope<T: Decodable>: Decodable { let data: T }
struct UserResponse: Decodable { let user: Account }
struct Bootstrap: Decodable {
    let apiVersion: Int
    let csrfToken: String
    let sessionCookieName: String
    let sessionLifetimeSeconds: Int
}
public struct AccountConnection: Decodable, Equatable, Identifiable, Sendable {
    public let id: String
    public let name: String?
    public let protocolName: String
    public let state: String
    public let canDownload: Bool
    public let connectionManifestVersion: Int?
    public let connectionRecoveryAvailable: Bool?
    public var displayName: String { name?.isEmpty == false ? name! : "Подключение" }
    public var isAvailable: Bool { isAvailable(for: [.amneziawg]) }
    public func isAvailable(for transports: Set<VPNTransport>) -> Bool {
        guard canDownload else { return false }
        if ["wireguard", "amneziawg"].contains(protocolName) { return transports.contains(.amneziawg) }
        return protocolName == "trusttunnel" && transports.contains(.trusttunnel) && connectionManifestVersion == 1
    }
    enum CodingKeys: String, CodingKey {
        case id, name, state, canDownload, connectionManifestVersion, connectionRecoveryAvailable
        case protocolName = "protocol"
    }
}
public struct AccountConnectionPage: Decodable, Sendable {
    public struct Package: Decodable, Identifiable, Sendable {
        public struct Slot: Decodable, Sendable { public let config: AccountConnection? }
        public let id: String
        public let name: String
        public let deviceCount: Int
        public let slots: [Slot]
    }
    public struct Pagination: Decodable, Sendable {
        public let page: Int
        public let lastPage: Int
    }
    public let experimentalTrustTunnelAvailable: Bool?
    public let automaticConnectionAvailable: Bool?
    public let packages: [Package]
    public let configs: [AccountConnection]
    public let pagination: Pagination
    public var connections: [AccountConnection] { configs + packages.flatMap { $0.slots.compactMap(\.config) } }
}
public enum ClientError: Error, LocalizedError, Equatable {
    case invalidAddress, invalidResponse, insecureStorage, expiredSession, unavailable, wrongAccount, unverified
    case noFreeSlot, subscriptionRequired, unsupportedConfiguration
    case recoveryPending(retryAfter: Int)
    case server(status: Int, retryAfter: Int?)
    public var errorDescription: String? {
        switch self {
        case .recoveryPending: return "Переносим подключение на другой сервер…"
        case .unsupportedConfiguration: return "Для этого подключения обновите приложение Undercore."
        case .noFreeSlot: return "Нет свободного места или это устройство было удалено. Проверьте подписку в кабинете."
        case .subscriptionRequired: return "Для подключения нужна действующая подписка."
        case .invalidAddress, .invalidResponse: return "Не удалось прочитать ответ сервера. Попробуйте позже."
        case .insecureStorage: return "Не удалось сохранить вход в связке ключей. Разблокируйте Mac и попробуйте снова."
        case .expiredSession: return "Войдите в аккаунт снова."
        case .unavailable: return "Подключение пока недоступно. Проверьте его состояние в кабинете."
        case .wrongAccount: return "Это подключение принадлежит другому аккаунту. Выберите подключение после входа."
        case .unverified: return "Подтвердите почту в личном кабинете, затем обновите список."
        case let .server(status, retry):
            switch status {
            case 422: return "Проверьте почту и пароль. Вход с этими данными не выполнен."
            case 403: return "Доступ запрещён. Проверьте аккаунт в личном кабинете."
            case 419: return "Время ожидания истекло. Повторите действие."
            case 429: return retry.map { "Слишком много попыток. Повторите через \($0) сек." } ?? "Слишком много попыток. Попробуйте позже."
            default: return "Сервис временно недоступен. Попробуйте позже."
            }
        }
    }
}
public enum HTTPMethod: String { case get = "GET", post = "POST" }
public enum APILimits {
    public static let requestTimeout: TimeInterval = 20
    public static let resourceTimeout: TimeInterval = 30
}
public enum AccountEndpoints {
    public static let origin = URL(string: "https://undercore.ru")!
    public static let website = URL(string: "https://undercore.ru/dashboard")!
    public static let register = URL(string: "https://undercore.ru/register")!
    public static let forgotPassword = URL(string: "https://undercore.ru/forgot-password")!
    static let bootstrap = "/api/mobile/v1/bootstrap"
    static let login = "/login"
    static let logout = "/logout"
    static let account = "/me"
    static let connectDevice = "/api/internal/vpn/devices/connect"
    static func page(_ number: Int) throws -> String {
        guard (1...10000).contains(number) else { throw ClientError.invalidAddress }
        return "/api/internal/vpn?page=\(number)"
    }
    static func connectionRecovery(_ id: String) throws -> String {
        try configuration(id) + "/connection-recovery"
    }
    static func connectionManifest(_ id: String) throws -> String {
        try configuration(id) + "/connection-manifest"
    }
    static func configuration(_ id: String) throws -> String {
        guard id.range(of: "\\Avpn_[0-9A-HJKMNP-TV-Z]{26}\\z", options: .regularExpression) != nil else { throw ClientError.invalidAddress }
        return "/api/internal/vpn/configs/\(id)"
    }
}
