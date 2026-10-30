import Foundation
import XCTest
@testable import UndercoreMacCore

final class ProfileConfigurationTests: XCTestCase {
    // Synthetic non-production keys; never connect these fixtures.
    private let key = Data(repeating: 7, count: 32).base64EncodedString()
    private var valid: String {
        """
        [Interface]
        PrivateKey = \(key)
        Address = 10.99.0.2/32
        DNS = 1.1.1.1
        Jc = 4
        Jmin = 40
        Jmax = 70
        S1 = 32
        S2 = 32
        S3 = 32
        S4 = 32
        H1 = 100001-100010
        H2 = 200001-200010
        H3 = 300001-300010
        H4 = 400001-400010
        HeaderProtectionKey = \(key)
        ContentPaddingAddition = 8-16
        RekeyAfterTime = 100-110
        [Peer]
        PublicKey = \(key)
        Endpoint = vpn.example.test:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
        """
    }

    func testAWG31ParametersSurviveParsing() throws {
        let parsed = try ProfileConfiguration.parse(Data(valid.utf8))
        XCTAssertEqual(parsed.interface.cookieReplyPacketJunkSize, 32)
        XCTAssertEqual(parsed.interface.transportPacketJunkSize, 32)
        XCTAssertEqual(parsed.interface.headerProtectionKey?.base64Key, key)
        XCTAssertEqual(parsed.interface.contentPaddingAddition, "8-16")
        XCTAssertEqual(parsed.interface.rekeyAfterTime, "100-110")
        XCTAssertEqual(parsed.peers.count, 1)
        XCTAssertEqual(parsed.peers[0].allowedIPs.count, 2)
    }

    func testRejectsCommandHooksWithoutExposingSource() {
        let source = valid.replacingOccurrences(of: "DNS = 1.1.1.1", with: "PostUp = SECRET_SCRIPT")
        XCTAssertThrowsError(try ProfileConfiguration.parse(Data(source.utf8))) { error in
            XCTAssertFalse(error.localizedDescription.contains("SECRET_SCRIPT"))
            XCTAssertFalse(error.localizedDescription.contains(self.key))
        }
    }

    func testRejectsIncompleteOversizedAndBinaryInputs() {
        let invalid: [Data] = [Data(), Data(repeating: 65, count: 65_537), Data([255, 0, 255]),
            Data(valid.replacingOccurrences(of: "Address = 10.99.0.2/32", with: "").utf8),
            Data(valid.replacingOccurrences(of: "Endpoint = vpn.example.test:51820", with: "").utf8),
            Data(valid.replacingOccurrences(of: "AllowedIPs = 0.0.0.0/0, ::/0", with: "").utf8)]
        for data in invalid { XCTAssertThrowsError(try ProfileConfiguration.parse(data)) }
    }

    func testRejectsDuplicateAndUnknownKeys() {
        for line in ["PrivateKey = \(key)", "UnknownSecret = hidden"] {
            let source = valid.replacingOccurrences(of: "Address = 10.99.0.2/32", with: "Address = 10.99.0.2/32\n" + line)
            XCTAssertThrowsError(try ProfileConfiguration.parse(Data(source.utf8)))
        }
    }

    func testMetadataContainsNoConfiguration() throws {
        let data = try JSONEncoder().encode(ConnectionProfile(name: "Mac"))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["id", "name"])
    }
}
