#!/bin/bash
# Integrated Swift + Rust harness for proxy-path exit probing (§71):
# Swift EgressProbe.exchange (NWConnection on lo0 + SecTrust)
#   -> Rust OneShotBridge (127.0.0.1 + libproc PID check)
#   -> Rust split_proxy SOCKS5 client
#   -> local SOCKS5 proxy -> local TLS /cdn-cgi/trace server.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
LIB="$ROOT/core/target/release/libalwaysconnect_core.a"
[ -f "$LIB" ] || (cd "$ROOT/core" && cargo build --release --quiet)
cd "$WORK"
swiftc -D EGRESS_PROBE_TEST -O -parse-as-library \
    "$ROOT/Sources/Helper/EgressProbe.swift" \
    "$ROOT/core/scripts/EgressProxyBridgeHarness.swift" \
    "$LIB" -o bridge-harness 2>&1 | grep -v "was built for newer 'macOS' version" || true
[ -x ./bridge-harness ] || { echo "FAIL build bridge-harness" >&2; exit 1; }

ssl() { /usr/bin/openssl "$@" >/dev/null 2>&1; }
ssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=Egress Bridge Test CA' \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout ca.key -out ca.pem
ssl x509 -in ca.pem -outform DER -out ca.der
ssl req -newkey rsa:2048 -nodes -subj '/CN=protected.example.invalid' -keyout server.key -out server.csr
printf 'subjectAltName=DNS:protected.example.invalid\nextendedKeyUsage=serverAuth\n' > server.ext
ssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile server.ext -out server.pem

mkdir -p support
echo -n ZZ > mode.txt

python3 -I - <<'PY'
import select
import socket
import socketserver
import ssl
import subprocess
import threading

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("server.pem", "server.key")
names, requests, socks_targets = [], [], []
context.set_servername_callback(lambda sock, name, ctx: names.append(name))

class TraceTLSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with context.wrap_socket(self.request, server_side=True) as stream:
                req = bytearray()
                while b"\r\n\r\n" not in req:
                    chunk = stream.recv(4096)
                    if not chunk:
                        return
                    req.extend(chunk)
                requests.append(bytes(req))
                with open("mode.txt", "r") as f:
                    code = f.read().strip()
                body = f"loc={code}\nip=198.51.100.42\n".encode()
                stream.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                    + body
                )
        except (ssl.SSLError, ConnectionError, TimeoutError):
            pass

def make_socks(tls_port):
    class SocksHandler(socketserver.BaseRequestHandler):
        def handle(self):
            c = self.request
            try:
                head = c.recv(2)
                if len(head) < 2 or head[0] != 5:
                    return
                c.recv(head[1])
                c.sendall(b"\x05\x00")
                req = c.recv(4)
                if len(req) < 4 or req[1] != 1:
                    return
                if req[3] == 3:
                    n = c.recv(1)[0]
                    host = c.recv(n).decode()
                    port = int.from_bytes(c.recv(2), "big")
                else:
                    return
                socks_targets.append((host, port))
                if host != "protected.example.invalid" or port != 443:
                    c.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                    return
                up = socket.create_connection(("127.0.0.1", tls_port), timeout=5)
                c.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                try:
                    sockets = [c, up]
                    while sockets:
                        r, _, _ = select.select(sockets, [], [], 5.0)
                        if not r:
                            break
                        for s in r:
                            other = up if s is c else c
                            data = s.recv(16384)
                            if not data:
                                try:
                                    other.shutdown(socket.SHUT_WR)
                                except OSError:
                                    pass
                                sockets.remove(s)
                                continue
                            other.sendall(data)
                finally:
                    up.close()
            except OSError:
                pass
    return SocksHandler

with socketserver.ThreadingTCPServer(("127.0.0.1", 0), TraceTLSHandler) as tls_srv:
    tls_srv.daemon_threads = True
    tls_port = tls_srv.server_address[1]
    threading.Thread(target=tls_srv.serve_forever, daemon=True).start()
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), make_socks(tls_port)) as socks_srv:
        socks_srv.daemon_threads = True
        socks_port = socks_srv.server_address[1]
        threading.Thread(target=socks_srv.serve_forever, daemon=True).start()
        subprocess.run(
            ["./bridge-harness", "ca.der", str(socks_port), "mode.txt", "support"],
            check=True,
            timeout=30,
        )
        socks_srv.shutdown()
    tls_srv.shutdown()

# Exactly 5 HTTP requests: 1 (ZZ allow; 2nd call cached), 2 (YY block),
# 3 (recheck ZZ; next call cached), 4 (YY block before approve),
# 5 (YY re-probed after approve bumped epoch); 6th (untrusted CA) sent 0 HTTP!
assert len(requests) == 5, f"expected 5 HTTP requests (cache + untrusted CA guard), got {len(requests)}"
assert all(b"Host: protected.example.invalid\r\n" in r for r in requests)
assert len(socks_targets) == 6, f"expected 6 SOCKS5 opens, got {len(socks_targets)}"
assert all(t == ("protected.example.invalid", 443) for t in socks_targets)
assert len(names) == 6 and all(n == "protected.example.invalid" for n in names)
print("PASS Swift EgressProbe + Rust OneShotBridge + SOCKS5 + TLS full cross-language chain")
PY
