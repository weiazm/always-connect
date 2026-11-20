#!/usr/bin/env python3
"""Egress gate harness helpers (DESIGN.md §66.13). Three roles:

server      test sites behind the test gateway: TLS on :443 (answers
            /cdn-cgi/trace with a per-name country), plain HTTP on :80,
            a raw TCP service, and UDP listeners; logs every arrival.
controller  the gate's controller: sends the group config, answers each
            check by probing through the tunnel with the ALPN marker.
probe       one egress probe (run inside the client network namespace).

Test names and countries are fixtures only (*.test, ZZ/YY).
"""
import argparse, json, os, secrets, socket, ssl, subprocess, sys, threading, time

LOC = {"protected.test": "ZZ", "blocked.test": "YY", "range.test": "ZZ"}


def jlog(path, **kw):
    kw["t"] = time.time()
    with open(path, "a") as f:
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
            body = (f"ip={peer[0]}\nloc={LOC.get(sni, 'ZZ')}\n" if path == "/cdn-cgi/trace" else f"ok {sni}")
            s.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}".encode())
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
                     (serve_raw, (a.range_ip, 7000, a.log)), (serve_udp, (a.ip, 443, a.log)),
                     (serve_udp, (a.ip, 9999, a.log))]:
        threading.Thread(target=fn, args=args, daemon=True).start()
    open(a.ready, "w").close()
    while True:
        time.sleep(3600)


# Groups (DESIGN §66.3): member -> "probe" or "follow"; expected countries.
GROUPS = {
    1: {"names": ["protected.test"], "cidrs": [], "members": {"protected.test": "probe"}, "expect": ["ZZ"]},
    2: {"names": ["blocked.test", "*.blocked.test"], "cidrs": [],
        "members": {"blocked.test": "probe", "follow.blocked.test": "follow"}, "expect": ["ZZ"]},
    3: {"names": ["range.test"], "cidrs": ["10.250.0.2/32"], "members": {"range.test": "probe"}, "expect": ["ZZ"]},
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
    cfg = {"probe_alpn": marker, "groups": [{"id": g, "names": v["names"], "cidrs": v["cidrs"]} for g, v in GROUPS.items()]}
    conn.sendall((json.dumps(cfg) + "\n").encode())
    lock = threading.Lock()

    def check(group, host):
        t0 = time.time()
        g = GROUPS[group]
        if host in g["members"] and g["members"][host] == "probe":
            targets = [host]
        else:
            targets = [m for m, mode in g["members"].items() if mode == "probe"]
        locs = []
        for h in targets:
            try:
                out = subprocess.run(["ip", "netns", "exec", a.ns, sys.executable, "-I", __file__, "probe", "--host", h,
                                      "--ip", a.site_ip, "--alpn", marker, "--ca", a.ca],
                                     capture_output=True, text=True, timeout=3)
                locs.append(out.stdout.strip() or None)
            except Exception:
                locs.append(None)
        ok = bool(targets) and all(l in g["expect"] for l in locs)
        jlog(a.log, kind="check", group=group, host=host, probed=targets, locs=locs, ok=ok, ms=int((time.time() - t0) * 1000))
        with lock:
            conn.sendall((json.dumps({"verdict": {"group": group, "ok": ok}}) + "\n").encode())

    buf = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            msg = json.loads(line)
            if "check" in msg:
                c = msg["check"]
                threading.Thread(target=check, args=(c["group"], c.get("host")), daemon=True).start()


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
    body = data.split(b"\r\n\r\n", 1)[-1].decode()
    kv = dict(l.split("=", 1) for l in body.splitlines() if "=" in l)
    print(kv.get("loc", ""))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("server")
    s.add_argument("--ip"); s.add_argument("--range-ip"); s.add_argument("--cert"); s.add_argument("--key")
    s.add_argument("--log"); s.add_argument("--ready")
    c = sub.add_parser("controller")
    c.add_argument("--sock"); c.add_argument("--ns"); c.add_argument("--ca"); c.add_argument("--site-ip")
    c.add_argument("--log"); c.add_argument("--ready")
    r = sub.add_parser("probe")
    r.add_argument("--host"); r.add_argument("--ip"); r.add_argument("--alpn"); r.add_argument("--ca")
    a = p.parse_args()
    {"server": cmd_server, "controller": cmd_controller, "probe": cmd_probe}[a.cmd](a)


if __name__ == "__main__":
    main()
