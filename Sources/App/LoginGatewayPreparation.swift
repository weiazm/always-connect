import Foundation
import Network
import Security

/// One TLS connection during explicitly confirmed direct networking. Rust owns
/// the result lifetime and its binding to the selected host and port.
final class LoginGatewayPreparation {
    private let queue = DispatchQueue(label: "com.alwaysconnect.login-gateway")
    private let preparation = ac_login_preparation_new()
    private var connection: NWConnection?
    private var timeout: DispatchWorkItem?
    private var request: UInt64?
    private var certificateVerified = false

    #if LOGIN_GATEWAY_PREPARATION_TEST
    var testAnchor: SecCertificate?
    var onTestFinish: (() -> Void)?
    #endif

    deinit {
        timeout?.cancel()
        connection?.forceCancel()
        ac_login_preparation_free(preparation)
    }

    /// The caller has confirmed that direct networking was explicitly allowed
    /// and no connection intent is active. An unknown firewall state cannot
    /// start preparation.
    func confirmDirect() {
        queue.sync { ac_login_preparation_confirm_direct(preparation) }
    }

    func prepareWhileDirect(_ target: GatewayAddress) {
        queue.sync {
            let deadline = DispatchTime.now() + .seconds(2)
            let token = ac_login_preparation_begin(preparation, target.host, target.port)
            guard token != 0 else { return }
            stopTransport()
            request = token
            startTransport(target, token: token, deadline: deadline)
        }
    }

    func takeForIntent(_ target: GatewayAddress?) -> String? {
        takeResultForIntent(target).address
    }

    /// Consume the matching ready result and synchronously cancel in-flight
    /// I/O. Only a completed system trust rejection sets the failure flag.
    func takeResultForIntent(_ target: GatewayAddress?) -> (address: String?, certificateRejected: Bool) {
        queue.sync {
            stopTransport()
            var rejected = false
            guard let raw = ac_login_preparation_take_result_for_intent(
                preparation, target?.host, target?.port ?? 0, &rejected
            ) else { return (nil, rejected) }
            defer { ac_login_preparation_freeString(raw) }
            return (String(cString: raw), rejected)
        }
    }

    func cancel() {
        _ = takeForIntent(nil)
    }

    private func startTransport(_ target: GatewayAddress, token: UInt64, deadline: DispatchTime) {
        guard let port = NWEndpoint.Port(rawValue: target.port) else {
            finish(token)
            return
        }
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        let endpointHost = target.host.hasPrefix("[") && target.host.hasSuffix("]")
            ? String(target.host.dropFirst().dropLast()) : target.host
        let host = endpointHost.hasSuffix(".") ? String(endpointHost.dropLast()) : endpointHost
        let policy = SecPolicyCreateSSL(true, host as CFString)
        sec_protocol_options_set_tls_server_name(options, host)
        sec_protocol_options_set_tls_resumption_enabled(options, false)
        sec_protocol_options_set_peer_authentication_required(options, true)

        sec_protocol_options_set_verify_block(options, { [weak self] _, trust, complete in
            guard let self, self.request == token else { complete(false); return }
            let object = sec_trust_copy_ref(trust).takeRetainedValue()
            guard SecTrustSetPolicies(object, policy) == errSecSuccess,
                  SecTrustSetNetworkFetchAllowed(object, false) == errSecSuccess else {
                complete(false)
                return
            }
            #if LOGIN_GATEWAY_PREPARATION_TEST
            if let anchor = self.testAnchor {
                guard SecTrustSetAnchorCertificates(object, [anchor] as CFArray) == errSecSuccess,
                      SecTrustSetAnchorCertificatesOnly(object, true) == errSecSuccess else {
                    complete(false)
                    return
                }
            }
            #endif
            let status = SecTrustEvaluateAsyncWithError(object, self.queue) { [weak self] trust, accepted, _ in
                guard let self, self.request == token else { complete(false); return }
                self.certificateVerified = accepted
                let rejected = !accepted && Self.isTrustRejection(trust)
                complete(accepted)
                if rejected { self.finish(token, certificateRejected: true) }
            }
            if status != errSecSuccess { complete(false) }
        }, queue)

        // Network.framework resolves the configured host and reports the
        // numeric remote endpoint of the connection that completed TLS.
        let stream = NWConnection(host: NWEndpoint.Host(endpointHost), port: port, using: NWParameters(tls: tls))
        connection = stream
        stream.stateUpdateHandler = { [weak self, weak stream] state in
            guard let self, self.request == token else { return }
            switch state {
            case .ready:
                let peer = self.certificateVerified ? Self.remoteAddress(of: stream, port: port) : nil
                self.finish(token, address: peer)
            case .failed, .cancelled:
                self.finish(token)
            default:
                break
            }
        }
        let timeout = DispatchWorkItem { [weak self] in self?.finish(token) }
        self.timeout = timeout
        queue.asyncAfter(deadline: deadline, execute: timeout)
        stream.start(queue: queue)
    }

    private static func isTrustRejection(_ trust: SecTrust) -> Bool {
        var result = SecTrustResultType.invalid
        guard SecTrustGetTrustResult(trust, &result) == errSecSuccess else { return false }
        switch result {
        case .deny, .recoverableTrustFailure, .fatalTrustFailure: return true
        default: return false
        }
    }

    private static func remoteAddress(of stream: NWConnection?, port: NWEndpoint.Port) -> String? {
        guard case .hostPort(let host, let remotePort) = stream?.currentPath?.remoteEndpoint,
              remotePort == port else { return nil }
        switch host {
        case .ipv4(let address): return address.debugDescription
        case .ipv6(let address): return address.debugDescription
        default: return nil
        }
    }

    private func finish(_ token: UInt64, address: String? = nil, certificateRejected: Bool = false) {
        guard request == token else { return }
        stopTransport()
        ac_login_preparation_finish(preparation, token, address, certificateRejected)
        #if LOGIN_GATEWAY_PREPARATION_TEST
        onTestFinish?()
        #endif
    }

    private func stopTransport() {
        request = nil
        certificateVerified = false
        timeout?.cancel()
        timeout = nil
        connection?.stateUpdateHandler = nil
        connection?.forceCancel()
        connection = nil
    }
}

@_silgen_name("ac_login_preparation_new")
private func ac_login_preparation_new() -> OpaquePointer
@_silgen_name("ac_login_preparation_free")
private func ac_login_preparation_free(_ preparation: OpaquePointer)
@_silgen_name("ac_login_preparation_confirm_direct")
private func ac_login_preparation_confirm_direct(_ preparation: OpaquePointer)
@_silgen_name("ac_login_preparation_begin")
private func ac_login_preparation_begin(_ preparation: OpaquePointer, _ host: UnsafePointer<CChar>, _ port: UInt16) -> UInt64
@_silgen_name("ac_login_preparation_finish")
private func ac_login_preparation_finish(_ preparation: OpaquePointer, _ token: UInt64,
                                         _ address: UnsafePointer<CChar>?, _ certificateRejected: Bool)
@_silgen_name("ac_login_preparation_take_result_for_intent")
private func ac_login_preparation_take_result_for_intent(_ preparation: OpaquePointer, _ host: UnsafePointer<CChar>?,
                                                        _ port: UInt16, _ certificateRejected: UnsafeMutablePointer<Bool>)
    -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free")
private func ac_login_preparation_freeString(_ text: UnsafeMutablePointer<CChar>)
