#!/bin/bash
# Gateway preparation harness: synthetic certificates and loopback sockets only.
# Pass an already built libalwaysconnect_core.a to test an isolated build.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ "$#" -eq 0 ]; then
    cargo build --manifest-path "$ROOT/core/Cargo.toml" --locked --release
fi
LIB=${1:-$ROOT/core/target/release/libalwaysconnect_core.a}
WORK=$(mktemp -d /tmp/ac-login-gateway.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

swiftc -D LOGIN_GATEWAY_PREPARATION_TEST -parse-as-library -module-name LoginGatewayHarness \
    "$ROOT/Sources/Shared/GatewayAddress.swift" "$ROOT/Sources/App/LoginGatewayPreparation.swift" \
    "$ROOT/Sources/Helper/LoginGatewayCache.swift" "$ROOT/core/scripts/LoginGatewayHarness.swift" \
    "$LIB" -o "$WORK/harness"

cd "$WORK"
ssl() { /usr/bin/openssl "$@" >/dev/null 2>&1; }
ssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=Login Gateway Test CA' \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout ca.key -out ca.pem
ssl x509 -in ca.pem -outform DER -out ca.der
ssl req -newkey rsa:2048 -nodes -subj '/CN=localhost' -keyout server.key -out server.csr
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' > server.ext
ssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
    -extfile server.ext -out server.pem
mkdir -m 700 support

python3 -I - <<'PY'
from socketserver import BaseRequestHandler, ThreadingTCPServer
import errno
import ssl
import subprocess
from threading import Thread
import time

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('server.pem', 'server.key')
mutual_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
mutual_context.load_cert_chain('server.pem', 'server.key')
mutual_context.load_verify_locations('ca.pem')
mutual_context.verify_mode = ssl.CERT_REQUIRED
# In TLS 1.2 the handshake cannot complete before client authentication.
mutual_context.maximum_version = ssl.TLSVersion.TLSv1_2


class TLS(BaseRequestHandler):
    context = context

    def handle(self):
        self.request.settimeout(3)
        try:
            with self.context.wrap_socket(self.request, server_side=True) as stream:
                stream.recv(1)
        except (ssl.SSLError, TimeoutError, ConnectionResetError):
            pass


class MutualTLS(TLS):
    context = mutual_context


class DelayedTLS(TLS):
    def handle(self):
        time.sleep(2.25)
        try:
            super().handle()
        except OSError as error:
            # Darwin can return EINVAL from getpeername after the client
            # forcibly closes the socket at the preparation deadline.
            if error.errno != errno.EINVAL:
                raise


class Silent(BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            while self.request.recv(4096):
                pass
        except (TimeoutError, ConnectionResetError):
            pass


with (
    ThreadingTCPServer(('127.0.0.1', 0), TLS) as tls,
    ThreadingTCPServer(('127.0.0.1', 0), Silent) as stalled,
    ThreadingTCPServer(('127.0.0.1', 0), MutualTLS) as mutual,
    ThreadingTCPServer(('127.0.0.1', 0), DelayedTLS) as delayed,
):
    for server in (tls, stalled, mutual, delayed):
        server.daemon_threads = True
        Thread(target=server.serve_forever, daemon=True).start()
    subprocess.run(['./harness', 'ca.der', str(tls.server_address[1]), str(stalled.server_address[1]),
                    str(mutual.server_address[1]), str(delayed.server_address[1]), 'support'],
                   check=True, timeout=20)
PY
