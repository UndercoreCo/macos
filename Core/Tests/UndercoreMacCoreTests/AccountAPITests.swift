import Foundation
import XCTest
@testable import UndercoreMacCore

@MainActor final class AccountAPITests: XCTestCase {
    private let configID = "vpn_01M3FEB230BJPNX5WWB51891WZ"
    private var bootstrap: String { "{\"data\":{\"apiVersion\":1,\"csrfToken\":\"csrf-token\",\"sessionCookieName\":\"session\",\"sessionLifetimeSeconds\":1209600}}" }
    private var user: String { "{\"user\":{\"id\":7,\"name\":\"Test\",\"email\":\"test@example.test\",\"isEmailVerified\":true}}" }
    private func client(store: MemorySession = MemorySession(), transports: Set<VPNTransport> = [.amneziawg]) throws -> AccountAPI {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AccountStub.self]
        configuration.httpCookieStorage = nil
        return try AccountAPI(store: store, urlSession: URLSession(configuration: configuration), supportedTransports: transports)
    }
    override func tearDown() { AccountStub.install([]); super.tearDown() }

    private func manifestSetup(version: Int = 1, recovery: Bool = false, canDownload: Bool = true, state: String = "active") -> [AccountStub.Reply] {
        [
            .init(path: "/api/mobile/v1/bootstrap", json: bootstrap),
            .init(path: "/me", json: user),
            .init(path: "/api/internal/vpn/configs/" + configID,
                  json: "{\"data\":{\"id\":\"\(configID)\",\"protocol\":\"amneziawg\",\"state\":\"\(state)\",\"canDownload\":\(canDownload),\"connectionManifestVersion\":\(version),\"connectionRecoveryAvailable\":\(recovery)}}")
        ]
    }
    private func manifestReply(token: String = "csrf-token") throws -> AccountStub.Reply {
        let key = Data(repeating: 7, count: 32).base64EncodedString()
        let config = "[Interface]\nPrivateKey = \(key)\nAddress = 10.99.0.2/32\n[Peer]\nPublicKey = \(key)\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0\n"
        let payload: [String: Any] = ["data": ["schema_version": 1, "device_id": configID,
            "connection_id": "connection_1", "node_id": "lab", "protocol": "amneziawg", "state": "active",
            "expires_at": "2099-01-01T00:00:00.000Z", "revision": 1,
            "configuration": ["protocol": "amneziawg", "version": 1, "format": "awg-quick", "data": config]]]
        return .init(path: "/api/internal/vpn/configs/" + configID + "/connection-manifest",
                     json: String(data: try JSONSerialization.data(withJSONObject: payload), encoding: .utf8)!,
                     cache: "private, no-store", inspect: { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "X-CSRF-TOKEN"), token)
        })
    }

    func testRepeatConnectionSkipsBootstrapButFetchesFreshAccountMetadataAndManifest() async throws {
        AccountStub.install(manifestSetup() + [try manifestReply()] +
                            Array(manifestSetup().dropFirst()) + [try manifestReply()])
        let api = try client(store: .authenticated())
        for _ in 0..<2 { _ = try await api.managedConfiguration(id: configID, ownerID: 7) }
        XCTAssertEqual(AccountStub.remaining, 0)
    }

    func testWarmSessionStillRejectsChangedOwnerAndUnverifiedEmail() async throws {
        for (updatedUser, expected) in [
            (user.replacingOccurrences(of: "\"id\":7", with: "\"id\":8"), ClientError.wrongAccount),
            (user.replacingOccurrences(of: "true", with: "false"), ClientError.unverified)
        ] {
            AccountStub.install(manifestSetup() + [try manifestReply(), .init(path: "/me", json: updatedUser)])
            let api = try client(store: .authenticated())
            _ = try await api.managedConfiguration(id: configID, ownerID: 7)
            do { _ = try await api.managedConfiguration(id: configID, ownerID: 7); XCTFail("Stale account accepted") }
            catch { XCTAssertEqual(error as? ClientError, expected) }
            XCTAssertEqual(AccountStub.remaining, 0)
        }
    }

    func testWarmSessionStillRejectsExpiredConnection() async throws {
        AccountStub.install(manifestSetup() + [try manifestReply()] +
                            Array(manifestSetup(canDownload: false, state: "expired").dropFirst()))
        let api = try client(store: .authenticated())
        _ = try await api.managedConfiguration(id: configID, ownerID: 7)
        do { _ = try await api.managedConfiguration(id: configID, ownerID: 7); XCTFail("Stale access accepted") }
        catch { XCTAssertEqual(error as? ClientError, .unavailable) }
        XCTAssertEqual(AccountStub.remaining, 0)
    }

    func testCSRFRejectionRefreshesTokenAndRepeatsAllAuthorizationChecks() async throws {
        var fresh = manifestSetup()
        fresh[0] = .init(path: "/api/mobile/v1/bootstrap",
                         json: bootstrap.replacingOccurrences(of: "csrf-token", with: "rotated-token"))
        AccountStub.install(manifestSetup() + [
            .init(path: "/api/internal/vpn/configs/" + configID + "/connection-manifest", status: 419, json: "{}")
        ] + fresh + [try manifestReply(token: "rotated-token")])
        let api = try client(store: .authenticated())
        _ = try await api.managedConfiguration(id: configID, ownerID: 7)
        XCTAssertEqual(AccountStub.remaining, 0)
    }

    func testCSRFRefreshCannotRetryUnderAnotherAccount() async throws {
        AccountStub.install(manifestSetup() + [
            .init(path: "/api/internal/vpn/configs/" + configID + "/connection-manifest", status: 419, json: "{}"),
            .init(path: "/api/mobile/v1/bootstrap", json: bootstrap),
            .init(path: "/me", json: user.replacingOccurrences(of: "\"id\":7", with: "\"id\":8"))
        ])
        let api = try client(store: .authenticated())
        do { _ = try await api.managedConfiguration(id: configID, ownerID: 7); XCTFail("Changed account accepted") }
        catch { XCTAssertEqual(error as? ClientError, .wrongAccount) }
        XCTAssertEqual(AccountStub.remaining, 0)
    }

    func testCSRFRefreshIsBoundedAndRejectedTokenIsNotReused() async throws {
        let failure = AccountStub.Reply(path: "/api/internal/vpn/configs/" + configID + "/connection-manifest", status: 419, json: "{}")
        AccountStub.install(manifestSetup() + [failure] + manifestSetup() + [failure])
        let api = try client(store: .authenticated())
        do { _ = try await api.managedConfiguration(id: configID, ownerID: 7); XCTFail("Unbounded retry") }
        catch { XCTAssertEqual(error as? ClientError, .server(status: 419, retryAfter: nil)) }
        XCTAssertEqual(AccountStub.remaining, 0)
        AccountStub.install(manifestSetup() + [try manifestReply()])
        _ = try await api.managedConfiguration(id: configID, ownerID: 7)
        XCTAssertEqual(AccountStub.remaining, 0)
    }

    func testNewProcessBootstrapsAgainInsteadOfPersistingCSRF() async throws {
        let store = MemorySession.authenticated()
        for _ in 0..<2 {
            AccountStub.install(manifestSetup() + [try manifestReply()])
            let api = try client(store: store)
            _ = try await api.managedConfiguration(id: configID, ownerID: 7)
            XCTAssertEqual(AccountStub.remaining, 0)
        }
        XCTAssertFalse(String(data: try JSONEncoder().encode(store.value), encoding: .utf8)!.contains("csrf-token"))
    }

    func testLogoutDuringCSRFRefreshCannotRestoreSessionOrDownload() async throws {
        let refreshing = expectation(description: "Refresh started")
        AccountStub.install(manifestSetup() + [
            .init(path: "/api/internal/vpn/configs/" + configID + "/connection-manifest", status: 419, json: "{}"),
            .init(path: "/api/mobile/v1/bootstrap", json: bootstrap, cookie: "session=late; Secure; Path=/",
                  delay: 0.1, inspect: { _ in refreshing.fulfill() })
        ])
        let store = MemorySession.authenticated()
        let api = try client(store: store)
        let task = Task { try await api.managedConfiguration(id: configID, ownerID: 7) }
        await fulfillment(of: [refreshing], timeout: 2)
        try api.clearSession()
        do { _ = try await task.value; XCTFail("Logged-out request accepted") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertNil(store.value)
        XCTAssertFalse(api.hasSession)
        XCTAssertEqual(AccountStub.remaining, 0)
    }

    func testRecoveryRefreshRechecksServerOptInBeforeRetryingMutation() async throws {
        AccountStub.install(manifestSetup(recovery: true) + [
            .init(path: "/api/internal/vpn/configs/" + configID + "/connection-recovery", status: 419, json: "{}")
        ] + manifestSetup(recovery: false))
        let api = try client(store: .authenticated())
        do { _ = try await api.recoverConnection(id: configID, ownerID: 7, expectedRevision: 1); XCTFail("Revoked recovery accepted") }
        catch { XCTAssertEqual(error as? ClientError, .server(status: 503, retryAfter: nil)) }
        XCTAssertEqual(AccountStub.remaining, 0)
    }

    func testDeviceCSRFRefreshPreservesIdempotentDeviceKey() async throws {
        let deviceKey = UUID()
        let inspect: (URLRequest) -> Void = { request in
            let stream = request.httpBodyStream!
            stream.open(); defer { stream.close() }
            var bytes = [UInt8](repeating: 0, count: 4096)
            let count = stream.read(&bytes, maxLength: bytes.count)
            let body = try! JSONSerialization.jsonObject(with: Data(bytes.prefix(count))) as! [String: String]
            XCTAssertEqual(body["deviceKey"], deviceKey.uuidString.lowercased())
        }
        let checks = Array(manifestSetup().prefix(2))
        AccountStub.install(checks + [
            .init(path: "/api/internal/vpn/devices/connect", status: 419, json: "{}", inspect: inspect)
        ] + checks + [
            .init(path: "/api/internal/vpn/devices/connect", status: 202,
                  json: "{\"data\":{\"id\":\"\(configID)\",\"protocol\":\"amneziawg\",\"state\":\"provisioning\",\"canDownload\":false}}", inspect: inspect)
        ])
        let api = try client(store: .authenticated())
        _ = try await api.connectDevice(key: deviceKey, name: "Mac", ownerID: 7)
        XCTAssertEqual(AccountStub.remaining, 0)
    }

    func testFailedTokenRefreshMustBeRetriedBeforeNextConnect() async throws {
        AccountStub.install(manifestSetup() + [
            .init(path: "/api/internal/vpn/configs/" + configID + "/connection-manifest", status: 419, json: "{}"),
            .init(path: "/api/mobile/v1/bootstrap", status: 503, json: "{}")
        ])
        let api = try client(store: .authenticated())
        do { _ = try await api.managedConfiguration(id: configID, ownerID: 7); XCTFail("Refresh failure ignored") }
        catch { XCTAssertEqual(error as? ClientError, .server(status: 503, retryAfter: nil)) }
        XCTAssertEqual(AccountStub.remaining, 0)
        AccountStub.install(manifestSetup() + [try manifestReply()])
        _ = try await api.managedConfiguration(id: configID, ownerID: 7)
        XCTAssertEqual(AccountStub.remaining, 0)
    }

    func testAdvertisedManifestUsesCapabilitiesAndCSRFWithoutLegacyExport() async throws {
        let key = Data(repeating: 7, count: 32).base64EncodedString()
        let config = "[Interface]\nPrivateKey = \(key)\nAddress = 10.99.0.2/32\n[Peer]\nPublicKey = \(key)\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0\n"
        let payload: [String: Any] = ["data": ["schema_version": 1, "device_id": configID,
            "connection_id": "connection_1", "node_id": "lab", "protocol": "amneziawg", "state": "active",
            "expires_at": "2099-01-01T00:00:00.000Z", "revision": 1,
            "configuration": ["protocol": "amneziawg", "version": 1, "format": "awg-quick", "data": config]]]
        let json = String(data: try JSONSerialization.data(withJSONObject: payload), encoding: .utf8)!
        AccountStub.install(manifestSetup() + [
            .init(path: "/api/internal/vpn/configs/" + configID + "/connection-manifest", json: json, cache: "private, no-store",
                  inspect: { request in
                      XCTAssertEqual(request.httpMethod, "POST")
                      XCTAssertEqual(request.value(forHTTPHeaderField: "X-CSRF-TOKEN"), "csrf-token")
                      let stream = request.httpBodyStream!
                      stream.open(); defer { stream.close() }
                      var bytes = [UInt8](repeating: 0, count: 4096)
                      let count = stream.read(&bytes, maxLength: bytes.count)
                      let body = try! JSONSerialization.jsonObject(with: Data(bytes.prefix(count))) as! [String: Any]
                      XCTAssertEqual(body["schema_version"] as? Int, 1)
                      XCTAssertNil(body["device_id"])
                      let offers = body["capabilities"] as! [[String: Any]]
                      XCTAssertEqual(offers.count, 1)
                      XCTAssertEqual(offers[0]["protocol"] as? String, "amneziawg")
                      XCTAssertEqual(offers[0]["configuration_version"] as? Int, 1)
                  })])
        let api = try client(store: .authenticated())
        let result = try await api.managedConfiguration(id: configID, ownerID: 7)
        XCTAssertEqual(result.data, Data(config.utf8))
        XCTAssertEqual(result.revisionScope, .connection(deviceID: configID, connectionID: "connection_1"))
        XCTAssertEqual(AccountStub.remaining, 0)
    }
    func testRecoveryUsesAuthenticatedOptInAndExpectedRevision() async throws {
        let key = Data(repeating: 7, count: 32).base64EncodedString()
        let config = "[Interface]\nPrivateKey = \(key)\nAddress = 10.99.0.2/32\n[Peer]\nPublicKey = \(key)\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0\n"
        let payload: [String: Any] = ["data": ["schema_version": 1, "device_id": configID,
            "connection_id": "connection_1", "node_id": "lab", "protocol": "amneziawg", "state": "active",
            "expires_at": "2099-01-01T00:00:00.000Z", "revision": 1,
            "configuration": ["protocol": "amneziawg", "version": 1, "format": "awg-quick", "data": config]]]
        let json = String(data: try JSONSerialization.data(withJSONObject: payload), encoding: .utf8)!
        AccountStub.install(manifestSetup(recovery: true, canDownload: false, state: "sync_error") + [
            .init(path: "/api/internal/vpn/configs/" + configID + "/connection-recovery", json: json, cache: "private, no-store",
                  inspect: { request in
                      XCTAssertEqual(request.httpMethod, "POST")
                      XCTAssertEqual(request.value(forHTTPHeaderField: "X-CSRF-TOKEN"), "csrf-token")
                      let stream = request.httpBodyStream!
                      stream.open(); defer { stream.close() }
                      var bytes = [UInt8](repeating: 0, count: 4096)
                      let count = stream.read(&bytes, maxLength: bytes.count)
                      let body = try! JSONSerialization.jsonObject(with: Data(bytes.prefix(count))) as! [String: Any]
                      XCTAssertEqual(body["schema_version"] as? Int, 1)
                      XCTAssertNil(body["device_id"])
                      XCTAssertEqual(body["expected_revision"] as? Int, 1)
                      let offers = body["capabilities"] as! [[String: Any]]
                      XCTAssertEqual(offers.count, 1)
                      XCTAssertEqual(offers[0]["protocol"] as? String, "amneziawg")
                      XCTAssertEqual(offers[0]["configuration_version"] as? Int, 1)
                  })])
        let api = try client(store: .authenticated())
        let result = try await api.recoverConnection(id: configID, ownerID: 7, expectedRevision: 1)
        XCTAssertEqual(result.data, Data(config.utf8))
        XCTAssertTrue(result.automaticRecoveryAllowed)
        XCTAssertEqual(result.revisionScope, .connection(deviceID: configID, connectionID: "connection_1"))
        XCTAssertEqual(AccountStub.remaining, 0)
    }
    func testOutageDownloadFailureIsTransientOnlyWhenServerAuthorizesRecovery() async throws {
        for (state, recovery, expected) in [
            ("sync_error", true, ClientError.server(status: 503, retryAfter: nil)),
            ("sync_error", false, ClientError.unavailable),
            ("expired", true, ClientError.unavailable),
            ("provisioning", true, ClientError.unavailable)
        ] {
            AccountStub.install(manifestSetup(recovery: recovery, canDownload: false, state: state))
            let api = try client(store: .authenticated())
            do { _ = try await api.managedConfiguration(id: configID, ownerID: 7); XCTFail("Unavailable download accepted") }
            catch { XCTAssertEqual(error as? ClientError, expected) }
            XCTAssertEqual(AccountStub.remaining, 0)
        }
    }

    func testOnlyExplicitRecoveryPendingIsEligibleForPolling() async throws {
        for code in ["VPN_RECOVERY_PENDING", "VPN_SERVICE_UNAVAILABLE"] {
            AccountStub.install(manifestSetup(recovery: true) + [
                .init(path: "/api/internal/vpn/configs/" + configID + "/connection-recovery", status: 503,
                      json: "{\"code\":\"\(code)\"}")])
            let api = try client(store: .authenticated())
            do { _ = try await api.recoverConnection(id: configID, ownerID: 7, expectedRevision: 1); XCTFail("Failure ignored") }
            catch {
                XCTAssertEqual(error as? ClientError, code == "VPN_RECOVERY_PENDING"
                    ? .recoveryPending(retryAfter: 30) : .server(status: 503, retryAfter: nil))
            }
            XCTAssertEqual(AccountStub.remaining, 0)
        }
    }
    func testRecoveryWithoutMetadataOptInNeverSendsMutation() async throws {
        AccountStub.install(manifestSetup())
        let api = try client(store: .authenticated())
        do { _ = try await api.recoverConnection(id: configID, ownerID: 7, expectedRevision: 1); XCTFail("Opt-in ignored") }
        catch { XCTAssertEqual(error as? ClientError, .server(status: 503, retryAfter: nil)) }
        XCTAssertEqual(AccountStub.remaining, 0)
    }
    func testManifestFailureNeverFallsBackToLegacy() async throws {
        for status in [403, 404, 409, 410, 503] {
            AccountStub.install(manifestSetup() + [.init(path: "/api/internal/vpn/configs/" + configID + "/connection-manifest", status: status, json: "{}")])
            let api = try client(store: .authenticated())
            do { _ = try await api.managedConfiguration(id: configID, ownerID: 7); XCTFail("Failure ignored") }
            catch {
                XCTAssertEqual(error as? ClientError, status == 409 ? .unavailable : .server(status: status, retryAfter: nil))
            }
            XCTAssertEqual(AccountStub.remaining, 0)
        }
    }
    func testUnknownAdvertisedManifestVersionFailsBeforeDownload() async throws {
        AccountStub.install(manifestSetup(version: 2))
        let api = try client(store: .authenticated())
        do { _ = try await api.managedConfiguration(id: configID, ownerID: 7); XCTFail("Future version accepted") }
        catch { XCTAssertEqual(error as? ClientError, .unsupportedConfiguration) }
        XCTAssertEqual(AccountStub.remaining, 0)
    }
    func testManifestRequiresNoStoreAndValidJSON() async throws {
        AccountStub.install(manifestSetup() + [.init(path: "/api/internal/vpn/configs/" + configID + "/connection-manifest", json: "{}")])
        let api = try client(store: .authenticated())
        do { _ = try await api.managedConfiguration(id: configID, ownerID: 7); XCTFail("Cacheable manifest accepted") }
        catch { XCTAssertEqual(error as? ClientError, .invalidResponse) }
        XCTAssertEqual(AccountStub.remaining, 0)
    }

    func testLoginRotatesCookieAndCSRFWithoutPersistingPassword() async throws {
        let store = MemorySession()
        AccountStub.install([
            .init(path: "/api/mobile/v1/bootstrap", json: bootstrap, cookie: "session=guest; Secure; Path=/"),
            .init(path: "/login", json: user, cookie: "session=authenticated; Secure; Path=/", inspect: { request in
                XCTAssertEqual(request.httpMethod, "POST")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Cookie"), "session=guest")
                XCTAssertEqual(request.value(forHTTPHeaderField: "X-CSRF-TOKEN"), "csrf-token")
                XCTAssertEqual(request.value(forHTTPHeaderField: "Origin"), "https://undercore.ru")
            }),
            .init(path: "/api/mobile/v1/bootstrap", json: bootstrap, inspect: { request in
                XCTAssertEqual(request.value(forHTTPHeaderField: "Cookie"), "session=authenticated")
            })
        ])
        let api = try client(store: store)
        let account = try await api.login(email: "test@example.test", password: "SYNTHETIC-PASSWORD")
        XCTAssertEqual(account.id, 7)
        XCTAssertEqual(store.value?.cookieValue, "authenticated")
        XCTAssertFalse(String(data: try JSONEncoder().encode(store.value), encoding: .utf8)!.contains("SYNTHETIC-PASSWORD"))
        XCTAssertEqual(AccountStub.remaining, 0)
    }
    func testUnauthorizedInvalidatesSavedSession() async throws {
        let store = MemorySession.authenticated()
        AccountStub.install([.init(path: "/api/internal/vpn", status: 401, json: "{}")])
        let api = try client(store: store)
        var invalidated = false
        api.onSessionInvalidated = { invalidated = true }
        do { _ = try await api.page(1); XCTFail("Expected rejection") }
        catch { XCTAssertEqual(error as? ClientError, .expiredSession) }
        XCTAssertNil(store.value)
        XCTAssertTrue(invalidated)
    }
    func testConfigurationCannotCrossAccountsOrReachDownload() async throws {
        AccountStub.install([
            .init(path: "/api/mobile/v1/bootstrap", json: bootstrap),
            .init(path: "/me", json: user)
        ])
        let api = try client(store: .authenticated())
        do { _ = try await api.configuration(id: configID, ownerID: 99); XCTFail("Expected owner guard") }
        catch { XCTAssertEqual(error as? ClientError, .wrongAccount) }
        XCTAssertEqual(AccountStub.remaining, 0)
    }
    func testUnavailableConnectionIsNotDownloaded() async throws {
        AccountStub.install([
            .init(path: "/api/mobile/v1/bootstrap", json: bootstrap),
            .init(path: "/me", json: user),
            .init(path: "/api/internal/vpn/configs/" + configID,
                  json: "{\"data\":{\"id\":\"\(configID)\",\"name\":null,\"protocol\":\"amneziawg\",\"state\":\"expired\",\"canDownload\":false}}")
        ])
        let api = try client(store: .authenticated())
        do { _ = try await api.configuration(id: configID, ownerID: 7); XCTFail("Expected unavailable guard") }
        catch { XCTAssertEqual(error as? ClientError, .unavailable) }
        XCTAssertEqual(AccountStub.remaining, 0)
    }
    func testConfigurationIsValidatedInMemory() async throws {
        let key = Data(repeating: 7, count: 32).base64EncodedString()
        let configuration = "[Interface]\nPrivateKey = \(key)\nAddress = 10.99.0.2/32\n[Peer]\nPublicKey = \(key)\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0\n"
        AccountStub.install([
            .init(path: "/api/mobile/v1/bootstrap", json: bootstrap),
            .init(path: "/me", json: user),
            .init(path: "/api/internal/vpn/configs/" + configID,
                  json: "{\"data\":{\"id\":\"\(configID)\",\"protocol\":\"amneziawg\",\"state\":\"active\",\"canDownload\":true}}"),
            .init(path: "/api/internal/vpn/configs/" + configID + "/configuration", json: configuration, mime: "application/octet-stream", revision: "3")
        ])
        let store = MemorySession.authenticated()
        let api = try client(store: store)
        let export = try await api.managedConfiguration(id: configID, ownerID: 7)
        XCTAssertEqual(export.data, Data(configuration.utf8))
        XCTAssertEqual(export.revision, 3)
        XCTAssertFalse(String(data: try JSONEncoder().encode(store.value), encoding: .utf8)!.contains(key))
    }
    func testRateLimitSurvivesLoginRetryAndIsScopedToOperation() async throws {
        AccountStub.install([
            .init(path: "/api/mobile/v1/bootstrap", json: bootstrap, cookie: "session=guest; Secure; Path=/"),
            .init(path: "/login", status: 429, json: "{}", retry: "60"),
            .init(path: "/api/mobile/v1/bootstrap", json: bootstrap, cookie: "session=guest; Secure; Path=/"),
            .init(path: "/api/internal/vpn", json: "{\"data\":{\"configs\":[],\"packages\":[],\"pagination\":{\"page\":1,\"lastPage\":1}}}")
        ])
        let api = try client()
        for _ in 0..<2 {
            do { _ = try await api.login(email: "test@example.test", password: "test"); XCTFail("Expected rate limit") }
            catch { guard case .server(status: 429, retryAfter: _) = error as? ClientError else { return XCTFail("Wrong error") } }
        }
        _ = try await api.page(1)
        XCTAssertEqual(AccountStub.remaining, 0)
    }
    func testLogoutClearsLocalSessionEvenWhenOffline() async throws {
        let store = MemorySession.authenticated()
        AccountStub.install([.init(path: "/api/mobile/v1/bootstrap", status: 503, json: "{}")])
        let api = try client(store: store)
        do { try await api.logout(); XCTFail("Expected network error") } catch {}
        XCTAssertNil(store.value)
        XCTAssertFalse(api.hasSession)
    }
    func testRedirectDoesNotBecomeLoginSuccess() async throws {
        AccountStub.install([.init(path: "/api/internal/vpn", status: 302, json: "<html></html>")])
        let api = try client(store: .authenticated())
        do { _ = try await api.page(1); XCTFail("Unexpected success") }
        catch { XCTAssertEqual(error as? ClientError, .server(status: 302, retryAfter: nil)) }
        let transport = try APITransport(baseURL: AccountEndpoints.origin, session: nil)
        for path in ["//evil.test/", "https://evil.test/", "/\\evil.test/"] {
            XCTAssertThrowsError(try transport.url(for: path))
        }
        XCTAssertThrowsError(try AccountEndpoints.configuration("../other"))
    }
    func testUntrustedSavedCookieIsDiscardedBeforeRequest() throws {
        let store = MemorySession()
        store.value = .init(origin: "https://undercore.ru", cookieName: "session", cookieValue: "bad\r\nInjected: value", expiresAt: Date().addingTimeInterval(3600))
        let api = try client(store: store)
        XCTAssertFalse(api.hasSession)
        XCTAssertNil(store.value)
    }
    func testClearFailureStillInvalidatesInMemorySession() throws {
        let store = MemorySession.authenticated()
        let api = try client(store: store)
        store.failClear = true
        var invalidated = false
        api.onSessionInvalidated = { invalidated = true }
        XCTAssertThrowsError(try api.clearSession())
        XCTAssertFalse(api.hasSession)
        XCTAssertTrue(invalidated)
    }
    func testTrustTunnelDeviceRequestUsesExplicitProtocolAndRejectsWrongResponse() async throws {
        for replyProtocol in ["trusttunnel", "amneziawg"] {
            AccountStub.install([
                .init(path: "/api/mobile/v1/bootstrap", json: bootstrap),
                .init(path: "/me", json: user),
                .init(path: "/api/internal/vpn/devices/connect", status: 202,
                      json: "{\"data\":{\"id\":\"\(configID)\",\"name\":\"Mac\",\"protocol\":\"\(replyProtocol)\",\"state\":\"provisioning\",\"canDownload\":false}}",
                      inspect: { request in
                          XCTAssertEqual(request.value(forHTTPHeaderField: "X-CSRF-TOKEN"), "csrf-token")
                      })
            ])
            let api = try client(store: .authenticated(), transports: [.amneziawg, .trusttunnel])
            do {
                let result = try await api.connectDevice(key: UUID(), name: "Mac", ownerID: 7, transport: .trusttunnel)
                XCTAssertEqual(replyProtocol, "trusttunnel")
                XCTAssertEqual(result.protocolName, "trusttunnel")
            } catch { XCTAssertEqual(replyProtocol, "amneziawg"); XCTAssertEqual(error as? ClientError, .invalidResponse) }
            XCTAssertEqual(AccountStub.remaining, 0)
        }
    }

    func testStandardClientCannotRequestExperimentalTransport() async throws {
        AccountStub.install([])
        let api = try client(store: .authenticated())
        do { _ = try await api.connectDevice(key: UUID(), name: "Mac", ownerID: 7, transport: .trusttunnel); XCTFail("Unsupported transport") }
        catch { XCTAssertEqual(error as? ClientError, .unsupportedConfiguration) }
    }

    func testAutomaticConnectionRequiresCurrentOwnerAndUsesCSRF() async throws {
        AccountStub.install([
            .init(path: "/api/mobile/v1/bootstrap", json: bootstrap),
            .init(path: "/me", json: user),
            .init(path: "/api/internal/vpn/devices/connect", status: 202,
                  json: "{\"data\":{\"id\":\"\(configID)\",\"name\":\"Mac\",\"protocol\":\"amneziawg\",\"state\":\"provisioning\",\"canDownload\":false}}",
                  inspect: { request in
                      XCTAssertEqual(request.httpMethod, "POST")
                      XCTAssertEqual(request.value(forHTTPHeaderField: "X-CSRF-TOKEN"), "csrf-token")
                  })
        ])
        let api = try client(store: .authenticated())
        let result = try await api.connectDevice(key: UUID(), name: "Mac", ownerID: 7)
        XCTAssertEqual(result.id, configID)
        XCTAssertFalse(result.isAvailable)
        XCTAssertEqual(AccountStub.remaining, 0)
    }
    func testAutomaticConnectionDoesNotConsumeSlotForDifferentOwner() async throws {
        AccountStub.install([.init(path: "/api/mobile/v1/bootstrap", json: bootstrap), .init(path: "/me", json: user)])
        let api = try client(store: .authenticated())
        do { _ = try await api.connectDevice(key: UUID(), name: "Mac", ownerID: 8); XCTFail("Owner mismatch accepted") }
        catch { XCTAssertEqual(error as? ClientError, .wrongAccount) }
        XCTAssertEqual(AccountStub.remaining, 0)
    }
    func testNoSubscriptionIsNotReportedAsBadLogin() async throws {
        AccountStub.install([
            .init(path: "/api/mobile/v1/bootstrap", json: bootstrap), .init(path: "/me", json: user),
            .init(path: "/api/internal/vpn/devices/connect", status: 422, json: "{\"code\":\"VPN_PAYMENT_REQUIRED\"}")
        ])
        let api = try client(store: .authenticated())
        do { _ = try await api.connectDevice(key: UUID(), name: "Mac", ownerID: 7); XCTFail("Expired grant accepted") }
        catch { XCTAssertEqual(error as? ClientError, .subscriptionRequired) }
    }
    func testOldFileProfileStillDecodesWithoutAccountBinding() throws {
        let data = Data("{\"id\":\"00000000-0000-0000-0000-000000000007\",\"name\":\"Local\"}".utf8)
        let profile = try JSONDecoder().decode(ConnectionProfile.self, from: data)
        XCTAssertNil(profile.accountConnection)
        XCTAssertEqual(profile.name, "Local")
    }
    func testPendingResponseCannotRestoreSessionAfterLogout() async throws {
        let store = MemorySession.authenticated()
        AccountStub.install([.init(path: "/api/internal/vpn", json: "{}", cookie: "session=late; Secure; Path=/", delay: 0.1)])
        let api = try client(store: store)
        let task = Task { try await api.page(1) }
        try await Task.sleep(for: .milliseconds(30))
        try api.clearSession()
        do { _ = try await task.value; XCTFail("Late response accepted") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertNil(store.value)
    }
}

private final class MemorySession: SessionStore {
    var value: SessionCredentials?
    var failClear = false
    static func authenticated() -> MemorySession {
        let store = MemorySession()
        store.value = .init(origin: "https://undercore.ru", cookieName: "session", cookieValue: "authenticated", expiresAt: Date().addingTimeInterval(3600))
        return store
    }
    func load() throws -> SessionCredentials? { value }
    func save(_ credentials: SessionCredentials) throws { value = credentials }
    func clear() throws {
        if failClear { throw ClientError.insecureStorage }
        value = nil
    }
}
private final class AccountStub: URLProtocol, @unchecked Sendable {
    struct Reply {
        let path: String
        var status = 200
        let json: String
        var cookie: String? = nil
        var mime = "application/json"
        var revision: String? = nil
        var retry: String? = nil
        var cache: String? = nil
        var delay: TimeInterval = 0
        var inspect: ((URLRequest) -> Void)? = nil
    }
    private static let lock = NSLock()
    private static var replies: [Reply] = []
    static var remaining: Int { lock.lock(); defer { lock.unlock() }; return replies.count }
    static func install(_ value: [Reply]) { lock.lock(); defer { lock.unlock() }; replies = value }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.lock.lock()
        let reply = Self.replies.isEmpty ? nil : Self.replies.removeFirst()
        Self.lock.unlock()
        guard let reply else { XCTFail("Unexpected network call"); client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse)); return }
        XCTAssertEqual(request.url?.path, reply.path)
        reply.inspect?(request)
        var headers = ["Content-Type": reply.mime]
        headers["Set-Cookie"] = reply.cookie
        headers["Retry-After"] = reply.retry
        headers["Cache-Control"] = reply.cache
        headers["X-Undercore-Configuration-Revision"] = reply.revision
        let response = HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: "HTTP/1.1", headerFields: headers)!
        let finish = { [self] in
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data(reply.json.utf8))
            client?.urlProtocolDidFinishLoading(self)
        }
        if reply.delay > 0 { DispatchQueue.global().asyncAfter(deadline: .now() + reply.delay, execute: finish) }
        else { finish() }
    }
    override func stopLoading() {}
}
