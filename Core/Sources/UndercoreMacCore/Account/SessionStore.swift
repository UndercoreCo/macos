import Foundation
import Security

public struct SessionCredentials: Codable, Equatable {
    public let origin: String
    public let cookieName: String
    public let cookieValue: String
    public let expiresAt: Date
    public init(origin: String, cookieName: String, cookieValue: String, expiresAt: Date) {
        self.origin = origin; self.cookieName = cookieName; self.cookieValue = cookieValue; self.expiresAt = expiresAt
    }
}
public protocol SessionStore {
    func load() throws -> SessionCredentials?
    func save(_ credentials: SessionCredentials) throws
    func clear() throws
}
public final class KeychainSessionStore: SessionStore {
    private let service: String
    public init(service: String) { self.service = service }
    private var query: [String: Any] { [kSecAttrSynchronizable as String: false, kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "session"] }
    public func load() throws -> SessionCredentials? {
        var query = query
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let result = SecItemCopyMatching(query as CFDictionary, &item)
        if result == errSecItemNotFound { return nil }
        guard result == errSecSuccess, let data = item as? Data else { throw ClientError.insecureStorage }
        do { return try JSONDecoder().decode(SessionCredentials.self, from: data) }
        catch { throw ClientError.insecureStorage }
    }
    public func save(_ credentials: SessionCredentials) throws {
        let data = try JSONEncoder().encode(credentials)
        let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        let updated = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updated == errSecItemNotFound {
            var item = query
            attributes.forEach { item[$0.key] = $0.value }
            guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { throw ClientError.insecureStorage }
        } else if updated != errSecSuccess { throw ClientError.insecureStorage }
    }
    public func clear() throws {
        let result = SecItemDelete(query as CFDictionary)
        guard result == errSecSuccess || result == errSecItemNotFound else { throw ClientError.insecureStorage }
    }
}
