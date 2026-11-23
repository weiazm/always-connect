import Darwin
import Foundation
import Network
import Security

// This binary starts in the verified root-private bundle. It drops every
// root credential before it opens a socket. It never reconnects.
private let queue = DispatchQueue(label: "alwaysconnect.pf-timing.https")

private enum ProbeResult: String {
    case ok, timeout, closed, failed
}

private func result(for error: NWError) -> ProbeResult {
    switch error {
    case .posix(.ETIMEDOUT): return .timeout
    case .posix(.ECONNRESET), .posix(.EPIPE), .posix(.ECONNABORTED), .posix(.ENOTCONN): return .closed
    default: return .failed
    }
}

private func report(_ result: ProbeResult, _ started: UInt64) {
    print("\(result.rawValue) \(started) \(DispatchTime.now().uptimeNanoseconds)")
    fflush(stdout)
}

private func headerResult(_ header: Data) -> ProbeResult {
    guard let text = String(data: header, encoding: .ascii) else { return .failed }
    let lines = text.components(separatedBy: "\r\n")
    let status = lines.first?.split(separator: " ", maxSplits: 2) ?? []
    guard status.count >= 2, status[0] == "HTTP/1.1", status[1].count == 3,
          let code = UInt16(status[1]), (200...299).contains(code) else { return .failed }
    for line in lines.dropFirst() {
        guard let split = line.firstIndex(of: ":") else { return .failed }
        let name = line[..<split].lowercased()
        let value = line[line.index(after: split)...].trimmingCharacters(in: .whitespaces).lowercased()
        switch name {
        case "connection":
            if value.split(separator: ",").contains(where: { $0.trimmingCharacters(in: .whitespaces) == "close" }) {
                return .failed
            }
        default: break
        }
    }
    return .ok
}

private func request(_ connection: NWConnection, content: Data, deadline: DispatchTime) -> ProbeResult {
    let sent = DispatchSemaphore(value: 0)
    var sendError: NWError?
    connection.send(content: content, completion: .contentProcessed { error in
        sendError = error
        sent.signal()
    })
    guard sent.wait(timeout: deadline) == .success else { return .timeout }
    if let sendError { return result(for: sendError) }

    let delimiter = Data([13, 10, 13, 10])
    var buffer = Data()
    while buffer.count < 4096 {
        let received = DispatchSemaphore(value: 0)
        var input: Data?
        var ended = false
        var receiveError: NWError?
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096 - buffer.count) { data, _, done, error in
            input = data
            ended = done
            receiveError = error
            received.signal()
        }
        guard received.wait(timeout: deadline) == .success else { return .timeout }
        if let receiveError { return result(for: receiveError) }
        if let input { buffer.append(input) }
        if let headerEnd = buffer.range(of: delimiter) {
            guard headerEnd.upperBound == buffer.endIndex, !ended else { return .failed }
            return headerResult(buffer[..<headerEnd.lowerBound])
        }
        if ended { return .closed }
    }
    return .failed
}

private func dropPrivileges(uid: uid_t, gid: gid_t) -> Bool {
    var group = gid
    return setgroups(1, &group) == 0 && setgid(gid) == 0 && setuid(uid) == 0
        && getuid() == uid && geteuid() == uid && getgid() == gid && getegid() == gid
        && setuid(0) != 0
}

private func runProbe() -> Int32 {
    guard getuid() == 0, geteuid() == 0,
          let uidText = readLine(), let uid = uid_t(uidText), uid >= 501,
          let gidText = readLine(), let gid = gid_t(gidText), gid > 0,
          dropPrivileges(uid: uid, gid: gid),
          let addressText = readLine(), let address = IPv4Address(addressText),
          let host = readLine(), let path = readLine(),
          let countText = readLine(), let count = Int(countText), (1...64).contains(count) else { return 1 }

    let tls = NWProtocolTLS.Options()
    let options = tls.securityProtocolOptions
    let policy = SecPolicyCreateSSL(true, host as CFString)
    sec_protocol_options_set_tls_server_name(options, host)
    sec_protocol_options_add_tls_application_protocol(options, "http/1.1")
    sec_protocol_options_set_peer_authentication_required(options, true)
    sec_protocol_options_set_tls_resumption_enabled(options, false)
    sec_protocol_options_set_verify_block(options, { _, trust, complete in
        let object = sec_trust_copy_ref(trust).takeRetainedValue()
        guard SecTrustSetPolicies(object, policy) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(object, false) == errSecSuccess else {
            complete(false)
            return
        }
        let status = SecTrustEvaluateAsyncWithError(object, queue) { _, accepted, _ in complete(accepted) }
        if status != errSecSuccess { complete(false) }
    }, queue)
    let connection = NWConnection(host: .ipv4(address), port: .https,
        using: NWParameters(tls: tls, tcp: NWProtocolTCP.Options()))
    defer { connection.cancel() }

    let ready = DispatchSemaphore(value: 0)
    var connected = false
    // Only the first terminal startup event writes the result. These callbacks
    // run serially on the connection queue and signal before the read below.
    var startupFinished = false
    connection.stateUpdateHandler = { state in
        guard !startupFinished else { return }
        switch state {
        case .ready: connected = true
        case .failed, .cancelled: break
        default: return
        }
        startupFinished = true
        ready.signal()
    }
    let began = DispatchTime.now()
    connection.start(queue: queue)
    guard ready.wait(timeout: began + .milliseconds(1_600)) == .success, connected else {
        report(.failed, began.uptimeNanoseconds)
        return 1
    }

    // The signed driver validates host/path and sends them through an anonymous
    // pipe. This request contains no cookies, credentials, or client identity.
    let content = Data("HEAD \(path) HTTP/1.1\r\nHost: \(host)\r\nConnection: keep-alive\r\n\r\n".utf8)
    for _ in 0..<count {
        let started = DispatchTime.now()
        let outcome = request(connection, content: content, deadline: started + .milliseconds(350))
        report(outcome, started.uptimeNanoseconds)
        if outcome != .ok { return 1 }
        let delay = (started + .milliseconds(100)).uptimeNanoseconds
        let now = DispatchTime.now().uptimeNanoseconds
        if delay > now { usleep(useconds_t((delay - now) / 1000)) }
    }
    return 0
}

exit(runProbe())
