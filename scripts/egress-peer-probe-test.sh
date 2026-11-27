#!/bin/bash
# Exercise a numeric peer with a DNS-name certificate on loopback.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
swiftc -D EGRESS_PROBE_TEST -parse-as-library "$ROOT/Sources/Helper/EgressProbe.swift" \
    "$ROOT/core/scripts/EgressPeerProbeHarness.swift" -o probe
# Also compile production EgressProbe (WITHOUT -D EGRESS_PROBE_TEST) to verify
# the #if !EGRESS_PROBE_TEST lo0 guard only permits 127.0.0.1 (§71).
cat > prod_probe.swift <<'SWIFT'
import Foundation
@main struct ProdLoopbackGuard {
    static func probe(host: String, ip: String?, port: Int) -> Bool {
        var req: [String: Any] = [
            "host": host, "port": port, "interface": "lo0", "timeoutMs": 1500,
            "alpn": ["http/1.1"],
            "request": "GET /cdn-cgi/trace HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n",
        ]
        if let ip { req["connectIp"] = ip }
        let text = String(decoding: try! JSONSerialization.data(withJSONObject: req), as: UTF8.self)
        var count = 0
        let bytes = text.withCString { EgressProbe.exchange($0, length: &count) }
        if let bytes { free(bytes); return true }
        return false
    }
    static func main() {
        let port = Int(CommandLine.arguments[1])!
        // Non-127.0.0.1 or nil connectIp on lo0 must be rejected before connecting.
        precondition(!probe(host: "blocked-v6.example.invalid", ip: "::1", port: port))
        precondition(!probe(host: "blocked-other.example.invalid", ip: "127.0.0.2", port: port))
        precondition(!probe(host: "blocked-nil.example.invalid", ip: nil, port: port))
        // 127.0.0.1 on lo0 is permitted to connect; production SecTrust rejects self-signed CA.
        precondition(!probe(host: "prod-lo0.example.invalid", ip: "127.0.0.1", port: port))
    }
}
SWIFT
swiftc -parse-as-library "$ROOT/Sources/Helper/EgressProbe.swift" prod_probe.swift -o prod_probe
ssl() { /usr/bin/openssl "$@" >/dev/null 2>&1; }
ssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=Egress Probe Test CA' \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout ca.key -out ca.pem
ssl x509 -in ca.pem -outform DER -out ca.der
ssl req -newkey rsa:2048 -nodes -subj '/CN=protected.example.invalid' -keyout server.key -out server.csr
printf 'subjectAltName=DNS:protected.example.invalid\nextendedKeyUsage=serverAuth\n' > server.ext
ssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile server.ext -out server.pem
python3 -I - <<'PY'
import socketserver
import ssl
import subprocess
import threading

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("server.pem", "server.key")
names, requests = [], []
context.set_servername_callback(lambda sock, name, ctx: names.append(name))

class Probe(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with context.wrap_socket(self.request, server_side=True) as stream:
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    data = stream.recv(4096)
                    if not data: return
                    request.extend(data)
                requests.append(bytes(request))
                stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nloc=ZZ\n")
        except (ssl.SSLError, ConnectionError, TimeoutError):
            pass

with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Probe) as server:
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    subprocess.run(["./probe", "ca.der", str(server.server_address[1])], check=True, timeout=20)
    subprocess.run(["./prod_probe", str(server.server_address[1])], check=True, timeout=20)
    server.shutdown()
assert len(requests) == 1 and b"Host: protected.example.invalid\r\n" in requests[0]
assert "protected.example.invalid" in names and "wrong.example.invalid" in names
# Production lo0 build reached TLS for 127.0.0.1 (sending SNI, then rejecting untrusted CA)
# and never even connected for ::1, 127.0.0.2 or nil connectIp.
assert "prod-lo0.example.invalid" in names
assert not any(n.startswith("blocked-") for n in names)
print("PASS numeric peer retains the original TLS identity and HTTP Host; production lo0 guard restricts to 127.0.0.1")
PY
