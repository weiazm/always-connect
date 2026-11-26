#!/bin/bash
# Hysteria2 interop with the official HyNetworks/hysteria server (DESIGN.md §七十):
# self-signed certificate + pinSHA256, TCP and UDP ASSOCIATE through our managed
# client + existing SOCKS5 relay, salamander obfuscation, wrong password, wrong
# certificate pin, unreachable server, and (on Linux with iptables) port hopping.
# Touches only loopback and a temporary directory.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
PIDS=()
IPTABLES_RULE=""

cleanup() {
    for p in "${PIDS[@]:-}"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
    if [ -n "$IPTABLES_RULE" ]; then
        sudo iptables -t nat -D $IPTABLES_RULE 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

HYSTERIA_TAG="app/v2.14.0"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "${OS}/${ARCH}" in
    linux/x86_64)
        ASSET="hysteria-linux-amd64"
        SHA256="fc25edff9948708cb00a4ff01f3bccde677660aca050133bb1ad46c6860362d2"
        ;;
    linux/aarch64|linux/arm64)
        ASSET="hysteria-linux-arm64"
        SHA256="e7c52241299fe85aba11e9d36e85d8d88ddbb5799ac0e33d272219d20e313bab"
        ;;
    darwin/arm64)
        ASSET="hysteria-darwin-arm64"
        SHA256="c68aa6677f15e572f997b346bcdf193b45a9dc9071b7e9555efffc8694c5ec05"
        ;;
    darwin/x86_64)
        ASSET="hysteria-darwin-amd64"
        SHA256="37a3ef3649b5a8fd24799b285d413b1d38afa71e2c4c1d564efe3c3b65880efe"
        ;;
    *)
        echo "unsupported platform for hysteria interop: ${OS}/${ARCH}" >&2
        exit 2
        ;;
esac

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print tolower($1)}'
    else
        shasum -a 256 "$1" | awk '{print tolower($1)}'
    fi
}

CACHE_DIR=${HYSTERIA_CACHE_DIR:-"$ROOT/.local-build/hysteria-cache"}
mkdir -p "$CACHE_DIR"
BIN="${HYSTERIA_BIN:-$CACHE_DIR/${ASSET}-${HYSTERIA_TAG#app/}}"
if [ ! -x "$BIN" ] || [ "$(sha256_of "$BIN")" != "$SHA256" ]; then
    URL="https://github.com/HyNetworks/hysteria/releases/download/${HYSTERIA_TAG}/${ASSET}"
    echo "downloading $ASSET ($HYSTERIA_TAG)..."
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 15 -o "$WORK/$ASSET" "$URL"
    [ "$(sha256_of "$WORK/$ASSET")" = "$SHA256" ] || { echo "SHA-256 mismatch for $ASSET" >&2; exit 1; }
    chmod 755 "$WORK/$ASSET"
    mv -f "$WORK/$ASSET" "$BIN"
fi

# Self-signed cert for localhost / 127.0.0.1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$WORK/server.key" -out "$WORK/server.crt" \
    -days 2 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
PIN=$(openssl x509 -in "$WORK/server.crt" -outform DER | shasum -a 256 2>/dev/null || openssl x509 -in "$WORK/server.crt" -outform DER | sha256sum)
PIN=$(echo "$PIN" | awk '{print tolower($1)}')

run_case() {
    local label=$1 port=$2 client_ports=$3 obfs=$4 obfs_pw=$5
    local auth="test-auth-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    local cfg="$WORK/server-${label}.json"
    local log="$WORK/server-${label}.log"
    if [ -n "$obfs" ]; then
        cat > "$cfg" <<EOF
{
  "listen": "127.0.0.1:${port}",
  "tls": { "cert": "$WORK/server.crt", "key": "$WORK/server.key" },
  "auth": { "type": "password", "password": "${auth}" },
  "obfs": { "type": "${obfs}", "${obfs}": { "password": "${obfs_pw}" } }
}
EOF
    else
        cat > "$cfg" <<EOF
{
  "listen": "127.0.0.1:${port}",
  "tls": { "cert": "$WORK/server.crt", "key": "$WORK/server.key" },
  "auth": { "type": "password", "password": "${auth}" }
}
EOF
    fi
    "$BIN" server -c "$cfg" --disable-update-check --log-format json >"$log" 2>&1 &
    local pid=$!
    PIDS+=("$pid")
    for _ in $(seq 1 40); do
        grep -q "server up and running" "$log" 2>/dev/null && break
        sleep 0.1
    done
    if ! grep -q "server up and running" "$log" 2>/dev/null; then
        echo "hysteria server ($label) did not start:" >&2
        cat "$log" >&2
        exit 1
    fi
    if ! (cd "$ROOT/core" && AC_HY2_BIN="$BIN" AC_HY2_SERVER="127.0.0.1:${client_ports}" \
            AC_HY2_PIN="$PIN" AC_HY2_AUTH="$auth" AC_HY2_OBFS="$obfs" AC_HY2_OBFS_PASS="$obfs_pw" \
            cargo test --lib interop_with_a_reference_hysteria2_server -- --ignored --nocapture); then
        echo "--- hysteria server log ($label) ---" >&2
        tail -40 "$log" >&2
        exit 1
    fi
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    echo "PASS hysteria2 interop ($label)"
}

echo "== 1 plain TLS + pinSHA256 (TCP, UDP, bad auth, bad pin, unreachable)"
run_case "plain" 28443 "28443" "" ""

echo "== 2 salamander obfuscation + pinSHA256"
run_case "salamander" 28444 "28444" "salamander" "salamander-test-secret"

if [ "$OS" = "linux" ] && command -v iptables >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    echo "== 3 port hopping via Linux iptables"
    IPTABLES_RULE="OUTPUT -o lo -p udp --dport 28500:28510 -j REDIRECT --to-ports 28445"
    sudo iptables -t nat -A $IPTABLES_RULE
    run_case "port-hopping" 28445 "28500-28510" "" ""
    sudo iptables -t nat -D $IPTABLES_RULE
    IPTABLES_RULE=""
fi

echo "PASS all hysteria2 interop checks"
