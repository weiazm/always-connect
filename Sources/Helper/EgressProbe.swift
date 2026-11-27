import Foundation
import Network
import Security

/// Sends only the bytes provided by Rust on a fresh, interface-bound TLS connection.
enum EgressProbe {
    private struct Request: Decodable {
        let host: String
        let connectIp: String?
        let port: UInt16
        let request: String
        let alpn: [String]
        let interface: String
        let timeoutMs: Int
    }

    #if EGRESS_PROBE_TEST
    static var testAnchor: SecCertificate?
    #endif

    static func exchange(_ json: UnsafePointer<CChar>, length: UnsafeMutablePointer<Int>,
                         peerBuffer: UnsafeMutablePointer<UInt8>? = nil, capacity: Int = 0) -> UnsafeMutablePointer<UInt8>? {
        guard let request = try? JSONDecoder().decode(Request.self, from: Data(String(cString: json).utf8)),
              let port = NWEndpoint.Port(rawValue: request.port), !request.interface.isEmpty else { return nil }
        let endpoint: NWEndpoint.Host
        if let address = request.connectIp {
            if let v4 = IPv4Address(address) { endpoint = .ipv4(v4) }
            else if let v6 = IPv6Address(address) { endpoint = .ipv6(v6) }
            else { return nil }
        } else {
            endpoint = NWEndpoint.Host(request.host)
        }
        let deadline = DispatchTime.now() + .milliseconds(request.timeoutMs)
        let queue = DispatchQueue(label: "com.alwaysconnect.egress-probe")
        let loopback = request.interface == "lo0"
        #if !EGRESS_PROBE_TEST
        if loopback {
            // Production lo0 probes are only permitted to the service's own
            // one-shot loopback bridge on 127.0.0.1 (DESIGN §71).
            guard request.connectIp == "127.0.0.1" else { return nil }
        }
        let monitor = NWPathMonitor(requiredInterfaceType: loopback ? .loopback : .other)
        #else
        let monitor = NWPathMonitor(requiredInterfaceType: .loopback)
        #endif
        let complete = DispatchSemaphore(value: 0)
        var connection: NWConnection?
        var response: Data?
        var buffer = Data()
        var finished = false
        var observedPeer: String?

        func finish(_ data: Data? = nil) {
            guard !finished else { return }
            finished = true
            if case .hostPort(let peer, let actualPort) = connection?.currentPath?.remoteEndpoint, actualPort == port {
                observedPeer = numericAddress(peer) ?? observedPeer
            }
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
            if request.connectIp != nil {
                let policy = SecPolicyCreateSSL(true, request.host as CFString)
                sec_protocol_options_set_peer_authentication_required(tls.securityProtocolOptions, true)
                sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, done in
                    let peer = sec_trust_copy_ref(trust).takeRetainedValue()
                    guard SecTrustSetPolicies(peer, policy) == errSecSuccess else { done(false); return }
                    #if EGRESS_PROBE_TEST
                    if let anchor = testAnchor {
                        guard SecTrustSetAnchorCertificates(peer, [anchor] as CFArray) == errSecSuccess,
                              SecTrustSetAnchorCertificatesOnly(peer, true) == errSecSuccess else { done(false); return }
                    }
                    #endif
                    let result = SecTrustEvaluateAsyncWithError(peer, queue) { _, accepted, _ in done(accepted) }
                    if result != errSecSuccess { done(false) }
                }, queue)
            }
            let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
            parameters.requiredInterface = interface
            let stream = NWConnection(host: endpoint, port: port, using: parameters)
            connection = stream
            stream.stateUpdateHandler = { [weak stream] state in
                guard !finished, let stream else { return }
                switch state {
                case .ready:
                    if case .hostPort(let peer, let actualPort) = stream.currentPath?.remoteEndpoint, actualPort == port {
                        observedPeer = numericAddress(peer)
                    }
                    if request.connectIp != nil {
                        guard case .hostPort(let peer, let actualPort) = stream.currentPath?.remoteEndpoint,
                              actualPort == port, sameAddress(peer, endpoint) else { finish(); return }
                    }
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
        if let observedPeer, let peerBuffer, observedPeer.utf8.count < capacity {
            let bytes = Array(observedPeer.utf8) + [0]
            _ = bytes.withUnsafeBufferPointer { bytes in
                memcpy(peerBuffer, bytes.baseAddress!, bytes.count)
            }
        }
        guard let response, !response.isEmpty,
              let bytes = malloc(response.count)?.assumingMemoryBound(to: UInt8.self) else { return nil }
        length.pointee = response.count
        response.copyBytes(to: bytes, count: response.count)
        return bytes
    }

    private static func sameAddress(_ a: NWEndpoint.Host, _ b: NWEndpoint.Host) -> Bool {
        switch (a, b) {
        case (.ipv4(let left), .ipv4(let right)): return left.rawValue == right.rawValue
        case (.ipv6(let left), .ipv6(let right)): return left.rawValue == right.rawValue
        default: return false
        }
    }

    private static func numericAddress(_ endpoint: NWEndpoint.Host) -> String? {
        let data: Data
        let family: Int32
        switch endpoint {
        case .ipv4(let value): data = value.rawValue; family = AF_INET
        case .ipv6(let value): data = value.rawValue; family = AF_INET6
        default: return nil
        }
        var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        return data.withUnsafeBytes { ptr in
            guard inet_ntop(family, ptr.baseAddress, &text, socklen_t(text.count)) != nil else { return nil }
            return String(cString: text)
        }
    }
}
