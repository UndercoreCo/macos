import Foundation
import Network
import Security

public enum VPNTransport: String, Sendable, Hashable {
    case amneziawg, trusttunnel
    var configurationFormat: String { self == .amneziawg ? "awg-quick" : "trusttunnel-toml" }
}

/// Explicit transport envelope. Legacy AWG bytes stay compatible with installed extensions.
public enum VPNTransportConfiguration {
    case amneziaWG(Data)
    case trustTunnel(TrustTunnelConfiguration)

    private struct Envelope: Codable {
        let transport: String
        let version: Int
        let endpoint: String
    }

    public static func parse(_ data: Data) throws -> Self {
        guard !data.isEmpty, data.count <= 131_072 else { throw ClientError.unsupportedConfiguration }
        if data.first == UInt8(ascii: "{") {
            guard let wrapper = try? JSONDecoder().decode(Envelope.self, from: data),
                  wrapper.transport == "trusttunnel", wrapper.version == 1 else {
                throw ClientError.unsupportedConfiguration
            }
            return .trustTunnel(try TrustTunnelConfiguration(document: wrapper.endpoint))
        }
        _ = try ProfileConfiguration.parse(data)
        return .amneziaWG(data)
    }

    static func trustTunnelEnvelope(_ endpoint: String) throws -> Data {
        _ = try TrustTunnelConfiguration(document: endpoint)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(Envelope(transport: "trusttunnel", version: 1, endpoint: endpoint))
    }
}

/// Deliberately accepts only the canonical endpoint document produced by our adapter.
/// This is not a general TOML importer. Listener, routing and logging are client policy.
public struct TrustTunnelConfiguration: CustomStringConvertible, CustomDebugStringConvertible {
    public let endpointDocument: String
    public let remoteAddress: String
    public var description: String { "TrustTunnelConfiguration(<redacted>)" }
    public var debugDescription: String { description }

    public init(document: String) throws {
        do { try self.init(validating: document) }
        catch { throw ClientError.unsupportedConfiguration }
    }

    private init(validating document: String) throws {
        guard document.utf8.count <= 65_536, !document.contains("\0") else { throw ClientError.invalidResponse }
        let lines = document.split(separator: "\n", omittingEmptySubsequences: true)
        guard lines.first == "[endpoint]" else { throw ClientError.invalidResponse }
        var fields: [String: Data] = [:]
        for line in lines.dropFirst() {
            guard let separator = line.range(of: " = ") else { throw ClientError.invalidResponse }
            let name = String(line[..<separator.lowerBound])
            guard fields[name] == nil else { throw ClientError.invalidResponse }
            fields[name] = Data(line[separator.upperBound...].utf8)
        }
        let required: Set<String> = ["hostname", "addresses", "username", "password", "has_ipv6", "skip_verification", "certificate", "upstream_protocol", "anti_dpi", "dns_upstreams"]
        guard Set(fields.keys) == required else { throw ClientError.invalidResponse }
        func value<T: Decodable>(_ key: String, _ type: T.Type) throws -> T {
            try JSONDecoder().decode(type, from: fields[key]!)
        }
        let hostname = try value("hostname", String.self)
        guard hostname.utf8.count <= 253,
              hostname.range(of: "\\A[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\\z", options: .regularExpression) != nil,
              hostname.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && $0.count <= 63 }),
              try value("skip_verification", Bool.self) == false,
              ["http2", "http3"].contains(try value("upstream_protocol", String.self)),
              try value("dns_upstreams", [String].self).isEmpty else { throw ClientError.invalidResponse }
        _ = try value("has_ipv6", Bool.self)
        _ = try value("anti_dpi", Bool.self)
        for (key, limit) in [("username", 255), ("password", 1024)] {
            let credential = try value(key, String.self)
            guard !credential.isEmpty, credential.utf8.count <= limit,
                  !credential.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else {
                throw ClientError.invalidResponse
            }
        }
        let addresses = try value("addresses", [String].self)
        guard (1...8).contains(addresses.count) else { throw ClientError.invalidResponse }
        var hosts: [String] = []
        for address in addresses {
            guard let url = URLComponents(string: "https://" + address),
                  let host = url.host, let port = url.port, (1...65535).contains(port),
                  url.user == nil, url.password == nil, url.path.isEmpty,
                  url.query == nil, url.fragment == nil else { throw ClientError.invalidResponse }
            let ip = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            guard IPv4Address(ip) != nil || IPv6Address(ip) != nil else { throw ClientError.invalidResponse }
            hosts.append(ip)
        }
        let certificate = try value("certificate", String.self)
        if !certificate.isEmpty {
            guard certificate.utf8.count <= 16384,
                  certificate.hasPrefix("-----BEGIN CERTIFICATE-----\n"),
                  certificate.trimmingCharacters(in: .newlines).hasSuffix("-----END CERTIFICATE-----") else { throw ClientError.invalidResponse }
            let base64 = certificate.replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
                .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "").filter { !$0.isWhitespace }
            guard let der = Data(base64Encoded: base64), SecCertificateCreateWithData(nil, der as CFData) != nil else {
                throw ClientError.invalidResponse
            }
        }
        // Regenerate values, preventing non-canonical quoting from reaching the native parser.
        var canonical = "[endpoint]\n"
        for key in required.sorted() {
            let object = try JSONSerialization.jsonObject(with: fields[key]!, options: [.fragmentsAllowed])
            let bytes = try JSONSerialization.data(withJSONObject: object, options: [.fragmentsAllowed, .withoutEscapingSlashes])
            canonical += key + " = " + String(decoding: bytes, as: UTF8.self) + "\n"
        }
        endpointDocument = canonical
        remoteAddress = hosts[0]
    }

    public var runtimeDocument: String {
        """
        loglevel = "error"
        vpn_mode = "general"
        killswitch_enabled = false
        [listener.tun]
        mtu_size = 1350
        change_system_dns = false
        included_routes = []
        excluded_routes = []
        \(endpointDocument)
        """
    }
}
