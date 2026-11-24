#!/usr/bin/env python3
"""Egress gate harness helpers (DESIGN.md §66.13). Three roles:

server      test sites behind the test gateway: TLS on :443 (answers
            /cdn-cgi/trace with a per-name country), plain HTTP on :80,
            a raw TCP service, and UDP listeners; logs every arrival.
controller  the gate's controller: sends the protected sites, answers each
            check by probing the connection's own server through the
            tunnel with the ALPN marker.
probe       one egress probe (run inside the client network namespace).

Test names and countries are fixtures only (*.test, ZZ/YY).
"""
import argparse, json, os, secrets, socket, ssl, subprocess, sys, threading, time

# The exit country each site reports; a name without one has no trace page.
LOC = {"protected.test": "ZZ", "blocked.test": "YY", "www.blocked.test": "YY"}


def jlog(logfile, **kw):
    kw["t"] = time.time()
    with open(logfile, "a") as f:
        f.write(json.dumps(kw) + "\n")


def read_head(conn):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    lines = data.split(b"\r\n")
    req = lines[0].decode(errors="replace").split(" ")
    hdr = {}
    for l in lines[1:]:
        if b":" in l:
            k, v = l.split(b":", 1)
            hdr[k.strip().lower().decode()] = v.strip().decode(errors="replace")
    return (req[1] if len(req) > 1 else ""), hdr


def serve_tls(ip, cert, key, log):
    tl = threading.local()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["http/1.1"])
    ctx.sni_callback = lambda s, name, c: setattr(tl, "sni", name)
    srv = socket.create_server((ip, 443))

    def one(c, peer):
        try:
            tl.sni = None
            s = ctx.wrap_socket(c, server_side=True)
            sni = tl.sni
            jlog(log, kind="handshake", sni=sni)
            path, hdr = read_head(s)
            probe = hdr.get("user-agent", "") == "egress-check"
            jlog(log, kind="tls-request", sni=sni, path=path, probe=probe)
            trace = path == "/cdn-cgi/trace"
            body = (f"ip={peer[0]}\nloc={LOC[sni]}\n" if trace and sni in LOC else "no trace" if trace else f"ok {sni}")
            status = "404 Not Found" if trace and sni not in LOC else "200 OK"
            s.sendall(f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}".encode())
            s.close()
        except Exception as e:
            jlog(log, kind="tls-error", error=type(e).__name__)

    while True:
        c, peer = srv.accept()
        threading.Thread(target=one, args=(c, peer), daemon=True).start()


def serve_http(ip, log):
    srv = socket.create_server((ip, 80))
    while True:
        c, _ = srv.accept()
        path, hdr = read_head(c)
        host = hdr.get("host", "")
        jlog(log, kind="http-request", host=host, path=path)
        body = f"ok {host}"
        c.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}".encode())
        c.close()


def serve_raw(ip, port, log):
    srv = socket.create_server((ip, port))
    while True:
        c, _ = srv.accept()
        data = c.recv(4096)
        jlog(log, kind="raw", port=port, data=data.decode(errors="replace"))
        c.sendall(b"pong")
        c.close()


def serve_udp(ip, port, log):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, port))
    while True:
        data, _ = s.recvfrom(4096)
        jlog(log, kind="udp", port=port)


def cmd_server(a):
    for fn, args in [(serve_tls, (a.ip, a.cert, a.key, a.log)), (serve_http, (a.ip, a.log)),
                     (serve_raw, (a.ip, 7000, a.log)), (serve_raw, (a.range_ip, 7000, a.log)), (serve_udp, (a.ip, 443, a.log)),
                     (serve_udp, (a.ip, 9999, a.log))]:
        threading.Thread(target=fn, args=args, daemon=True).start()
    open(a.ready, "w").close()
    while True:
        time.sleep(3600)


# Rules (DESIGN §66.25): protected sites (with subdomains) and allowed countries.
GROUPS = {
    1: {"sites": ["protected.test"], "expect": ["ZZ"]},
    2: {"sites": ["blocked.test"], "expect": ["ZZ"]},
    3: {"sites": ["untraced.test"], "expect": ["ZZ"]},
}


def cmd_controller(a):
    marker = "ac-probe-" + secrets.token_hex(8)
    if os.path.exists(a.sock):
        os.unlink(a.sock)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(a.sock)
    os.chmod(a.sock, 0o600)
    srv.listen(1)
    open(a.ready, "w").close()
    conn, _ = srv.accept()
    groups = {**GROUPS, 4: {"sites": [f"ipcidr:{a.range_ip}/32"], "expect": ["ZZ"]}}
    cfg = {"probe_alpn": marker, "groups": [{"id": g, "sites": v["sites"]} for g, v in groups.items()]}
    conn.sendall((json.dumps(cfg) + "\n").encode())
    lock = threading.Lock()

    def check(group, host, dest, request_id):
        t0 = time.time()
        loc, at = None, None
        if host:
            try:
                out = subprocess.run(["ip", "netns", "exec", a.ns, sys.executable, "-I", __file__, "probe", "--host", host,
                                      "--ip", dest, "--alpn", marker, "--ca", a.ca],
                                     capture_output=True, text=True, timeout=3)
                loc = out.stdout.strip() or None
                at = time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1_000_000
            except (OSError, subprocess.TimeoutExpired):
                pass
        if loc is None:
            result = "block" if group == 4 else "unverified"
        else:
            result = "allow" if loc in groups[group]["expect"] else "block"
        jlog(a.log, kind="check", group=group, host=host, ip=dest, loc=loc, result=result, ms=int((time.time() - t0) * 1000))
        verdict = {"group": group, "requestId": request_id, "result": result}
        if result == "allow":
            verdict["evidenceAtMs"] = at
        with lock:
            conn.sendall((json.dumps({"verdict": verdict}) + "\n").encode())

    buf = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            try:
                msg = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                continue
            if "check" in msg:
                c = msg["check"]
                threading.Thread(target=check, args=(c["group"], c["host"], c["ip"], c["requestId"]), daemon=True).start()


def cmd_probe(a):
    ctx = ssl.create_default_context(cafile=a.ca)
    ctx.set_alpn_protocols(["http/1.1", a.alpn])
    s = ctx.wrap_socket(socket.create_connection((a.ip, 443), timeout=2.5), server_hostname=a.host)
    s.sendall(f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {a.host}\r\nUser-Agent: egress-check\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    if b" 200 " not in head.split(b"\r\n", 1)[0]:
        return
    body = body.decode()
    kv = dict(l.split("=", 1) for l in body.splitlines() if "=" in l)
    print(kv.get("loc", ""))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("server")
    s.add_argument("--ip"); s.add_argument("--range-ip"); s.add_argument("--cert"); s.add_argument("--key")
    s.add_argument("--log"); s.add_argument("--ready")
    c = sub.add_parser("controller")
    c.add_argument("--sock"); c.add_argument("--ns"); c.add_argument("--ca"); c.add_argument("--range-ip", required=True)
    c.add_argument("--log"); c.add_argument("--ready")
    r = sub.add_parser("probe")
    r.add_argument("--host"); r.add_argument("--ip"); r.add_argument("--alpn"); r.add_argument("--ca")
    a = p.parse_args()
    {"server": cmd_server, "controller": cmd_controller, "probe": cmd_probe}[a.cmd](a)


if __name__ == "__main__":
    main()
