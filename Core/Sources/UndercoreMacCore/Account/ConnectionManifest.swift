import Foundation

/// Wire DTO for the authenticated orchestrator contract. Never persisted or included in diagnostics.
struct ConnectionManifest: Decodable {
    struct Configuration: Decodable {
        let protocolName: String
        let version: Int
        let format: String
        let data: String
        enum CodingKeys: String, CodingKey { case protocolName = "protocol", version, format, data }
    }
    let schemaVersion: Int
    let deviceID: String
    let connectionID: String
    let nodeID: String
    let protocolName: String
    let state: String
    let expiresAt: String
    let revision: Int
    let configuration: Configuration
    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version", deviceID = "device_id", connectionID = "connection_id"
        case nodeID = "node_id", protocolName = "protocol", state, expiresAt = "expires_at", revision, configuration
    }

    func validated(deviceID expectedID: String, now: Date, automaticRecoveryAllowed: Bool = false, supportedTransports: Set<VPNTransport> = [.amneziawg]) throws -> ManagedConfiguration {
        guard schemaVersion == 1, let transport = VPNTransport(rawValue: protocolName),
              supportedTransports.contains(transport), configuration.protocolName == protocolName,
              configuration.version == 1, configuration.format == transport.configurationFormat else {
            throw ClientError.unsupportedConfiguration
        }
        guard deviceID == expectedID, state == "active",
              connectionID.range(of: "\\A[A-Za-z0-9_-]{1,100}\\z", options: .regularExpression) != nil,
              nodeID.range(of: "\\A[A-Za-z0-9_-]{1,100}\\z", options: .regularExpression) != nil,
              (1...2_147_483_647).contains(revision),
              expiresAt.range(of: "\\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z\\z", options: .regularExpression) != nil else {
            throw ClientError.invalidResponse
        }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let expiry = formatter.date(from: expiresAt), formatter.string(from: expiry) == expiresAt,
              expiry > now else { throw ClientError.unavailable }
        let raw = Data(configuration.data.utf8)
        let bytes = try transport == .trusttunnel ? VPNTransportConfiguration.trustTunnelEnvelope(configuration.data) : raw
        guard !raw.contains(0), raw.count <= ProfileConfiguration.maximumBytes else { throw ClientError.invalidResponse }
        return try ManagedConfiguration(data: bytes, revision: revision,
            revisionScope: .connection(deviceID: deviceID, connectionID: connectionID), expiresAt: expiry, automaticRecoveryAllowed: automaticRecoveryAllowed)
    }
}

struct ConnectionCapabilities: Encodable {
    struct Capability: Encodable {
        let protocolName: String
        let configurationVersion: Int
        enum CodingKeys: String, CodingKey { case protocolName = "protocol", configurationVersion = "configuration_version" }
    }
    let expectedRevision: Int?
    init(expectedRevision: Int? = nil, transports: Set<VPNTransport> = [.amneziawg]) {
        self.expectedRevision = expectedRevision
        capabilities = transports.sorted { $0.rawValue < $1.rawValue }.map { Capability(protocolName: $0.rawValue, configurationVersion: 1) }
    }
    let schemaVersion = 1
    // Advertise only a transport this build can actually run, never a future engine.
    let capabilities: [Capability]
    enum CodingKeys: String, CodingKey { case schemaVersion = "schema_version", capabilities, expectedRevision = "expected_revision" }
}
