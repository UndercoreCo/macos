#if !USE_NETWORK_EXTENSION
import Darwin
import Foundation

/// One authenticated Unix stream, no config on disk or in process arguments.
final class HelperConnection: @unchecked Sendable {
    private let fd: Int32
    private let lock = NSLock()
    private var closed = false

    init(path: String) throws {
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure.start }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8CString)
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            Darwin.close(fd); throw Failure.start
        }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes.map { UInt8(bitPattern: $0) }) }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard result == 0, getpeereid(fd, &uid, &gid) == 0, uid == 0 else {
            Darwin.close(fd); throw Failure.start
        }
        var noSignal: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
        var timeout = timeval(tv_sec: 3, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    }

    func send(_ data: Data) throws {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { throw Failure.start }
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                guard count > 0 else { throw Failure.start }
                offset += count
            }
        }
    }

    /// Called only on a background task; helper emits short fixed status lines.
    func receiveLine() throws -> String? {
        var bytes: [UInt8] = []
        while bytes.count < 256 {
            var byte: UInt8 = 0
            let count = Darwin.read(fd, &byte, 1)
            if count == 0 { return nil }
            guard count > 0 else { throw Failure.start }
            if byte == 10 { return String(bytes: bytes, encoding: .utf8) }
            bytes.append(byte)
        }
        throw Failure.start
    }

    func close() {
        lock.lock(); defer { lock.unlock() }
        if !closed { closed = true; shutdown(fd, SHUT_RDWR) }
    }
    deinit { Darwin.close(fd) }
}

#endif
