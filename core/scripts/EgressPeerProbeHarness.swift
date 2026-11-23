import Foundation
import Security

/// Exercises the same TLS exchange as the service, using a private loopback test CA.
@main struct EgressPeerProbeHarness {
    static func response(host: String, ip: String, port: Int) -> String? {
        let request: [String: Any] = [
            "host": host, "connectIp": ip, "port": port, "interface": "lo0", "timeoutMs": 2400,
            "alpn": ["http/1.1"],
            "request": "GET /cdn-cgi/trace HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n",
        ]
        let text = String(decoding: try! JSONSerialization.data(withJSONObject: request), as: UTF8.self)
        var count = 0
        var remote = [UInt8](repeating: 0, count: 64)
        let bytes = remote.withUnsafeMutableBufferPointer { buffer in
            text.withCString { EgressProbe.exchange($0, length: &count, peerBuffer: buffer.baseAddress, capacity: buffer.count) }
        }
        guard let bytes else { return nil }
        defer { free(bytes) }
        precondition(String(decoding: remote.prefix { $0 != 0 }, as: UTF8.self) == ip)
        return String(decoding: UnsafeBufferPointer(start: bytes, count: count), as: UTF8.self)
    }

    static func main() throws {
        let certificate = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let port = Int(CommandLine.arguments[2])!
        let host = "protected.example.invalid"
        EgressProbe.testAnchor = SecCertificateCreateWithData(nil, certificate as CFData)
        precondition(response(host: host, ip: "127.0.0.1", port: port)?.contains("loc=ZZ") == true)
        precondition(response(host: "wrong.example.invalid", ip: "127.0.0.1", port: port) == nil)
        precondition(response(host: host, ip: "::1", port: port) == nil)
        precondition(response(host: host, ip: "localhost", port: port) == nil)
        EgressProbe.testAnchor = nil
        precondition(response(host: host, ip: "127.0.0.1", port: port) == nil)
    }
}
