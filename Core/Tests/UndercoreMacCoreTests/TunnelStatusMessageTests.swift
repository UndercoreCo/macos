import Foundation
import XCTest
@testable import UndercoreMacCore

final class TunnelStatusMessageTests: XCTestCase {
    func testCountersDiscardKeysAndRejectAmbiguousRuntime() {
        let raw = "private_key=secret\npublic_key=secret\nlast_handshake_time_sec=123\ntx_bytes=40\nrx_bytes=80\n"
        XCTAssertEqual(TunnelCounters.parse(raw)?.diagnostic, .counters(handshake: true, sent: 40, received: 80))
        XCTAssertNil(TunnelCounters.parse(raw + "tx_bytes=90\n"))
        XCTAssertNil(TunnelCounters.parse("last_handshake_time_sec=1\ntx_bytes=-1\nrx_bytes=2"))
        XCTAssertNil(TunnelCounters.parse("tx_bytes=1\nrx_bytes=2"))
        XCTAssertNil(TunnelCounters.parse(String(repeating: "x", count: 65537)))
    }
    func testReplyCannotCrossRequestsOrTunnelGenerations() throws {
        let request = UUID(), run = UUID(), check = UUID()
        let reply = TunnelStatusReply(requestID: request, runID: run, checkID: check, codes: [.health(.checking), .counters(handshake: false, sent: 0, received: 0)])
        let data = try JSONEncoder().encode(reply)
        XCTAssertNotNil(TunnelStatusReply.decode(data, requestID: request, runID: run))
        XCTAssertNil(TunnelStatusReply.decode(data, requestID: UUID(), runID: run))
        XCTAssertNil(TunnelStatusReply.decode(data, requestID: request, runID: UUID()))
        let invalid = TunnelStatusReply(requestID: request, runID: run, checkID: check, codes: [.lifecycle(.closed)])
        XCTAssertNil(TunnelStatusReply.decode(try JSONEncoder().encode(invalid), requestID: request, runID: run))
        XCTAssertNil(TunnelStatusReply.decode(Data(repeating: 32, count: 4097), requestID: request, runID: run))
    }
    func testRequestsRejectUnknownCommandsAndVersions() throws {
        let request = TunnelStatusRequest(command: .check)
        let data = try JSONEncoder().encode(request)
        XCTAssertEqual(TunnelStatusRequest.decode(data)?.id, request.id)
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertNil(TunnelStatusRequest.decode(Data(text.replacingOccurrences(of: "check", with: "exportKeys").utf8)))
        XCTAssertNil(TunnelStatusRequest.decode(Data(text.replacingOccurrences(of: "\"version\":1", with: "\"version\":2").utf8)))
    }
}
