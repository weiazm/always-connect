#!/bin/bash
# Exercise a numeric peer with a DNS-name certificate on loopback.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
swiftc -D EGRESS_PROBE_TEST -parse-as-library "$ROOT/Sources/Helper/EgressProbe.swift" \
    "$ROOT/core/scripts/EgressPeerProbeHarness.swift" -o probe
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
    server.shutdown()
assert len(requests) == 1 and b"Host: protected.example.invalid\r\n" in requests[0]
assert "protected.example.invalid" in names and "wrong.example.invalid" in names
print("PASS numeric peer retains the original TLS identity and HTTP Host; invalid peer or trust sends no HTTP")
PY
