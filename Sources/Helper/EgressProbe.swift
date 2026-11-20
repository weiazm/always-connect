import Foundation
import Network
import Security

/// Sends only the bytes provided by Rust on a fresh, interface-bound TLS connection.
enum EgressProbe {
    private struct Request: Decodable {
        let host: String
        let port: UInt16
        let request: String
        let alpn: [String]
        let interface: String
        let timeoutMs: Int
    }

    static func exchange(_ json: UnsafePointer<CChar>, length: UnsafeMutablePointer<Int>) -> UnsafeMutablePointer<UInt8>? {
        guard let request = try? JSONDecoder().decode(Request.self, from: Data(String(cString: json).utf8)),
              let port = NWEndpoint.Port(rawValue: request.port), !request.interface.isEmpty else { return nil }
        let deadline = DispatchTime.now() + .milliseconds(request.timeoutMs)
        let queue = DispatchQueue(label: "com.alwaysconnect.egress-probe")
        let monitor = NWPathMonitor(requiredInterfaceType: .other)
        let complete = DispatchSemaphore(value: 0)
        var connection: NWConnection?
        var response: Data?
        var buffer = Data()
        var finished = false

        func finish(_ data: Data? = nil) {
            guard !finished else { return }
            finished = true
            response = data
            monitor.cancel()
            connection?.cancel()
            complete.signal()
        }

        func receive(_ connection: NWConnection) {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536 - buffer.count) { data, _, eof, error in
                guard !finished else { return }
                if let data { buffer.append(data) }
                if error == nil && (eof || buffer.count == 65_536) { finish(buffer) }
                else if error != nil { finish() }
                else { receive(connection) }
            }
        }

        monitor.pathUpdateHandler = { path in
            guard !finished, connection == nil,
                  let interface = path.availableInterfaces.first(where: { $0.name == request.interface }) else { return }
            monitor.cancel()
            let tls = NWProtocolTLS.Options()
            for protocolName in request.alpn {
                sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, protocolName)
            }
            sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, request.host)
            let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
            parameters.requiredInterface = interface
            let stream = NWConnection(host: NWEndpoint.Host(request.host), port: port, using: parameters)
            connection = stream
            stream.stateUpdateHandler = { [weak stream] state in
                guard !finished, let stream else { return }
                switch state {
                case .ready:
                    stream.send(content: Data(request.request.utf8), completion: .contentProcessed { error in
                        guard !finished else { return }
                        if error != nil { finish() } else { receive(stream) }
                    })
                case .failed, .cancelled:
                    finish()
                default: break
                }
            }
            stream.start(queue: queue)
        }
        monitor.start(queue: queue)
        queue.asyncAfter(deadline: deadline) { finish() }
        complete.wait()
        guard let response, !response.isEmpty,
              let bytes = malloc(response.count)?.assumingMemoryBound(to: UInt8.self) else { return nil }
        length.pointee = response.count
        response.copyBytes(to: bytes, count: response.count)
        return bytes
    }
}
