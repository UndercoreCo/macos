import Foundation
import CryptoKit

/// Session and repository for the existing website API. No password/configuration disk cache.
@MainActor public final class AccountAPI {
    private let transport: APITransport
    private let session: APISession
    private let now: () -> Date
    private let supportedTransports: Set<VPNTransport>
    private var generation = 0
    private var cooldowns: [String: Date] = [:]
    public var onSessionInvalidated: (() -> Void)?
    public var hasSession: Bool { session.isValid }

    public init(store: SessionStore, baseURL: URL = AccountEndpoints.origin,
                urlSession: URLSession? = nil, supportedTransports: Set<VPNTransport> = [.amneziawg], now: @escaping () -> Date = Date.init) throws {
        transport = try APITransport(baseURL: baseURL, session: urlSession)
        session = try APISession(origin: baseURL, store: store, now: now)
        self.now = now
        self.supportedTransports = supportedTransports
    }
    public func login(email: String, password: String) async throws -> Account {
        try clearSession()
        try await bootstrap()
        let body = try JSONEncoder().encode(["email": email.trimmingCharacters(in: .whitespacesAndNewlines), "password": password])
        let (data, _) = try await perform(AccountEndpoints.login, method: .post, body: body)
        let response: UserResponse = try decode(data)
        // Login rotates both the cookie and CSRF token.
        try await bootstrap()
        return response.user
    }
    public func currentAccount() async throws -> Account {
        guard hasSession else { throw ClientError.expiredSession }
        if !session.hasCSRFToken { try await bootstrap() }
        let (data, _) = try await perform(AccountEndpoints.account)
        let response: UserResponse = try decode(data)
        return response.user
    }
    public func page(_ number: Int) async throws -> AccountConnectionPage {
        let (data, _) = try await perform(AccountEndpoints.page(number))
        let response: Envelope<AccountConnectionPage> = try decode(data)
        guard response.data.pagination.page == number,
              response.data.pagination.lastPage >= number else { throw ClientError.invalidResponse }
        return response.data
    }
    public func connectDevice(key: UUID, name: String, ownerID: Int, transport requestedTransport: VPNTransport = .amneziawg) async throws -> AccountConnection {
        try await refreshingCSRFIfNeeded {
            try await self.requestDevice(key: key, name: name, ownerID: ownerID, requestedTransport: requestedTransport)
        }
    }

    private func requestDevice(key: UUID, name: String, ownerID: Int, requestedTransport: VPNTransport) async throws -> AccountConnection {
        guard supportedTransports.contains(requestedTransport) else { throw ClientError.unsupportedConfiguration }
        let account = try await currentAccount()
        guard account.id == ownerID else { throw ClientError.wrongAccount }
        guard account.isEmailVerified else { throw ClientError.unverified }
        let body = try JSONEncoder().encode(["deviceKey": key.uuidString.lowercased(), "name": String(name.prefix(80)), "protocol": requestedTransport.rawValue])
        let (data, _) = try await perform(AccountEndpoints.connectDevice, method: .post, body: body)
        let response: Envelope<AccountConnection> = try decode(data)
        guard response.data.protocolName == requestedTransport.rawValue else { throw ClientError.invalidResponse }
        return response.data
    }

    public func connection(id: String) async throws -> AccountConnection {
        let (data, _) = try await perform(AccountEndpoints.configuration(id))
        let response: Envelope<AccountConnection> = try decode(data)
        guard response.data.id == id else { throw ClientError.invalidResponse }
        return response.data
    }

    /// Revalidate the account and server permissions on every explicit connect.
    public func configuration(id: String, ownerID: Int) async throws -> Data {
        try await managedConfiguration(id: id, ownerID: ownerID).data
    }

    public func managedConfiguration(id: String, ownerID: Int) async throws -> ManagedConfiguration {
        try await managedConfiguration(id: id, ownerID: ownerID, recoveryRevision: nil)
    }

    public func recoverConnection(id: String, ownerID: Int, expectedRevision: Int) async throws -> ManagedConfiguration {
        guard (1...2_147_483_647).contains(expectedRevision) else { throw ClientError.invalidResponse }
        return try await managedConfiguration(id: id, ownerID: ownerID, recoveryRevision: expectedRevision)
    }

    private func managedConfiguration(id: String, ownerID: Int, recoveryRevision: Int?) async throws -> ManagedConfiguration {
        try await refreshingCSRFIfNeeded {
            try await self.requestConfiguration(id: id, ownerID: ownerID, recoveryRevision: recoveryRevision)
        }
    }

    private func requestConfiguration(id: String, ownerID: Int, recoveryRevision: Int?) async throws -> ManagedConfiguration {
        let started = generation
        let account = try await currentAccount()
        guard account.id == ownerID else { throw ClientError.wrongAccount }
        guard account.isEmailVerified else { throw ClientError.unverified }
        let path = try AccountEndpoints.configuration(id)
        let (metadata, _) = try await perform(path)
        let response: Envelope<AccountConnection> = try decode(metadata)
        guard response.data.id == id else { throw ClientError.invalidResponse }
        if !response.data.isAvailable(for: supportedTransports) {
            // The server separately authorizes recovery of a paid grant during a node outage.
            // Download availability is not the same as entitlement to request a replacement node.
            guard response.data.state == "sync_error",
                  response.data.connectionManifestVersion == 1,
                  response.data.connectionRecoveryAvailable == true,
                  (response.data.protocolName == "wireguard" ? supportedTransports.contains(.amneziawg) : supportedTransports.contains(where: { $0.rawValue == response.data.protocolName })) else {
                throw ClientError.unavailable
            }
            if recoveryRevision == nil { throw ClientError.server(status: 503, retryAfter: nil) }
        }
        if recoveryRevision != nil, response.data.connectionRecoveryAvailable != true {
            throw ClientError.server(status: 503, retryAfter: nil)
        }
        if let version = response.data.connectionManifestVersion {
            guard version == 1 else { throw ClientError.unsupportedConfiguration }
            return try await connectionManifest(id: id, generation: started, recoveryRevision: recoveryRevision,
                automaticRecoveryAllowed: response.data.connectionRecoveryAvailable == true)
        }
        // Legacy is used only when metadata does not advertise a manifest, never after its failure.
        let (data, http) = try await perform(path + "/configuration")
        guard http.mimeType == "application/octet-stream", data.count <= ProfileConfiguration.maximumBytes else { throw ClientError.invalidResponse }
        guard generation == started else { throw CancellationError() }
        return try ManagedConfiguration(data: data,
            revisionHeader: http.value(forHTTPHeaderField: "X-Undercore-Configuration-Revision"))
    }
    private func connectionManifest(id: String, generation started: Int, recoveryRevision: Int?,
                                    automaticRecoveryAllowed: Bool) async throws -> ManagedConfiguration {
        let body = try JSONEncoder().encode(ConnectionCapabilities(expectedRevision: recoveryRevision, transports: supportedTransports))
        let path = try recoveryRevision == nil ? AccountEndpoints.connectionManifest(id) : AccountEndpoints.connectionRecovery(id)
        let (data, http) = try await perform(path, method: .post, body: body)
        guard generation == started else { throw CancellationError() }
        guard http.mimeType == "application/json", data.count <= 524_288,
              http.value(forHTTPHeaderField: "Cache-Control")?.lowercased().contains("no-store") == true else {
            throw ClientError.invalidResponse
        }
        let response: Envelope<ConnectionManifest> = try decode(data)
        return try response.data.validated(deviceID: id, now: now(), automaticRecoveryAllowed: automaticRecoveryAllowed, supportedTransports: supportedTransports)
    }

    public func logout() async throws {
        do {
            try await bootstrap()
            _ = try await perform(AccountEndpoints.logout, method: .post, body: Data("{}".utf8))
        } catch {
            try clearSession()
            throw error
        }
        try clearSession()
    }
    public func clearSession() throws {
        generation += 1
        // Clear memory even if the Keychain refuses deletion; surface the storage failure.
        defer { onSessionInvalidated?() }
        try session.clear()
    }
    /// A CSRF rejection happens before the server action. Retry at most once and
    /// repeat account/ownership/metadata checks, not just the rejected mutation.
    /// Transport errors and other HTTP failures must never replay a mutation here.
    private func refreshingCSRFIfNeeded<T>(_ operation: () async throws -> T) async throws -> T {
        let started = generation
        do { return try await operation() }
        catch ClientError.server(status: 419, retryAfter: _) {
            try Task.checkCancellation()
            guard generation == started else { throw CancellationError() }
            guard hasSession else { throw ClientError.expiredSession }
            session.invalidateCSRFToken()
            return try await operation()
        }
    }

    private func bootstrap() async throws {
        // A failed forced refresh must not leave a pre-login or rejected token reusable.
        session.invalidateCSRFToken()
        let (data, response) = try await perform(AccountEndpoints.bootstrap)
        let envelope: Envelope<Bootstrap> = try decode(data)
        let value = envelope.data
        guard value.apiVersion == 1, !value.csrfToken.isEmpty, value.csrfToken.count <= 1024,
              !value.csrfToken.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
              value.sessionCookieName.range(of: "\\A[A-Za-z0-9_-]{1,128}\\z", options: .regularExpression) != nil else { throw ClientError.invalidResponse }
        session.configure(value)
        try capture(response)
        session.setCSRFToken(value.csrfToken)
    }
    private func perform(_ path: String, method: HTTPMethod = .get, body: Data? = nil) async throws -> (Data, HTTPURLResponse) {
        if session.isExpired { try clearSession(); throw ClientError.expiredSession }
        var request = URLRequest(url: try transport.url(for: path))
        request.httpMethod = method.rawValue
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("ru", forHTTPHeaderField: "Accept-Language")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        try session.authorize(&request, method: method)
        let key = cooldownKey(path, method: method, body: body)
        cooldowns = cooldowns.filter { $0.value > now() }
        if let deadline = cooldowns[key] { throw ClientError.server(status: 429, retryAfter: Int(ceil(deadline.timeIntervalSince(now())))) }
        try Task.checkCancellation()
        let started = generation
        let (data, response) = try await transport.send(request)
        try Task.checkCancellation()
        guard generation == started else { throw CancellationError() }
        if response.statusCode == 401 {
            try clearSession()
            throw ClientError.expiredSession
        }
        try capture(response)
        if response.statusCode == 419, method != .get { session.invalidateCSRFToken() }
        guard (200..<300).contains(response.statusCode) else {
            if (path.hasSuffix("/connection-manifest") || path.hasSuffix("/connection-recovery")), response.statusCode == 409 {
                throw ClientError.unavailable
            }
            if path == AccountEndpoints.connectDevice,
               let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let code = envelope["code"] as? String {
                if code == "VPN_SLOT_CONFLICT" { throw ClientError.noFreeSlot }
                if code == "VPN_PAYMENT_REQUIRED" { throw ClientError.subscriptionRequired }
            }
            if path.hasSuffix("/connection-recovery"), response.statusCode == 503, data.count <= 65_536,
               let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               envelope["code"] as? String == "VPN_RECOVERY_PENDING" {
                throw ClientError.recoveryPending(retryAfter: min(max(retryAfter(response) ?? 30, 5), 60))
            }
            let retry = retryAfter(response)
            if response.statusCode == 429, cooldowns.count < 256 {
                cooldowns[key] = now().addingTimeInterval(TimeInterval(retry ?? 60))
            }
            throw ClientError.server(status: response.statusCode, retryAfter: retry)
        }
        guard data.count <= 2_097_152 else { throw ClientError.invalidResponse }
        return (data, response)
    }
    private func capture(_ response: HTTPURLResponse) throws {
        if try !session.captureCookie(response) { try clearSession(); throw ClientError.expiredSession }
    }
    private func decode<T: Decodable>(_ data: Data) throws -> T {
        guard let value = try? JSONDecoder().decode(T.self, from: data) else { throw ClientError.invalidResponse }
        return value
    }
    private func cooldownKey(_ path: String, method: HTTPMethod, body: Data?) -> String {
        var key = method.rawValue + " " + path.split(separator: "?")[0]
        if path == AccountEndpoints.login, let body,
           let fields = try? JSONDecoder().decode([String: String].self, from: body), let email = fields["email"] {
            key += " " + SHA256.hash(data: Data(email.lowercased().utf8)).map { String(format: "%02x", $0) }.joined()
        }
        return key
    }
    private func retryAfter(_ response: HTTPURLResponse) -> Int? {
        guard let raw = response.value(forHTTPHeaderField: "Retry-After") else { return nil }
        if let seconds = Int(raw) { return min(max(seconds, 1), 86400) }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss z"
        return formatter.date(from: raw).map { min(max(Int(ceil($0.timeIntervalSince(now()))), 1), 86400) }
    }
}
