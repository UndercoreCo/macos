import Foundation

/// Metadata only. The private configuration is stored separately in Keychain.
public struct ConnectionProfile: Codable, Equatable, Identifiable {
    public let id: UUID
    public var name: String
    public let accountConnection: AccountBinding?

    public struct AccountBinding: Codable, Equatable, Sendable {
        public let accountID: Int
        public let configurationID: String
        public init(accountID: Int, configurationID: String) {
            self.accountID = accountID; self.configurationID = configurationID
        }
    }

    public init(id: UUID = UUID(), name: String, accountConnection: AccountBinding? = nil) {
        self.id = id
        self.name = name
        self.accountConnection = accountConnection
    }
}
