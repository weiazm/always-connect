#!/usr/bin/env python3
"""Sample DNS and two certificate-verified HTTPS paths on macOS. Emit redacted JSON lines."""
import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import re
import subprocess
import time


def command(args, timeout):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired:
        return 124, ""


def route(address):
    _, output = command(["/sbin/route", "-n", "get", address], 3)
    match = re.search(r"^\s*interface:\s*(\S+)", output, re.M)
    if not match:
        return "unknown"
    return "tunnel" if match[1].startswith("utun") else "other"


def https(host, pin=None):
    args = ["/usr/bin/curl", "-q", "-4", "-sSI", "--connect-timeout", "3",
            "--max-time", "5", "-o", "/dev/null", "-w",
            "%{http_code} %{time_namelookup} %{time_appconnect} %{remote_ip}"]
    if pin is not None:
        args += ["--resolve", f"{host}:443:{pin}"]
    code, output = command(args + [f"https://{host}/"], 6)
    fields = output.split()
    result = {"exit": code, "http": int(fields[0]) if fields else 0}
    if len(fields) >= 3:
        result.update(dnsReadySeconds=float(fields[1]), tlsReadySeconds=float(fields[2]))
    peer = fields[3] if len(fields) >= 4 else None
    return result, peer


def forwarder_uses_loopback():
    _, output = command(["/usr/sbin/scutil", "--dns"], 3)
    return bool(re.search(r"nameserver\[\d+\]\s*:\s*127\.0\.0\.1\s*$", output, re.M))


def local_dns(host, use_tcp):
    code, output = command(["/usr/bin/dig", "@127.0.0.1", "+time=2", "+tries=1",
                            "+tcp" if use_tcp else "+notcp", "+noall", "+comments",
                            "+answer", host, "A"], 3)
    status = re.search(r"status: (\w+)", output)
    return {"exit": code, "status": status[1] if status else "no-response",
            "hasAddress": bool(re.search(r"\sIN\s+A\s+\d", output))}


def sample(host, pin):
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        normal = pool.submit(https, host)
        fixed = pool.submit(https, host, pin) if pin else None
        default_route = pool.submit(route, "default")
        pinned_route = pool.submit(route, pin) if pin else None
        dns = {}
        if forwarder_uses_loopback():
            dns = {name: pool.submit(local_dns, host, tcp)
                   for name, tcp in (("udp", False), ("tcp", True))}
        normal_result, normal_peer = normal.result()
        output = {"utc": started, "defaultRoute": default_route.result(),
                  "normal": normal_result, "localDNS": {k: v.result() for k, v in dns.items()}}
        if fixed:
            result, peer = fixed.result()
            result.update(route=pinned_route.result(), reachedPin=peer == pin,
                          sameNormalPeer=(normal_peer == peer) if normal_peer and peer else None)
            output["pinned"] = result
        # A proxy's peer is not the origin. Learn a pin from the normal path only
        # if the system resolver also returned that address for the selected host.
        if pin is None and normal_peer and normal_result["exit"] == 0 and normal_result["http"]:
            _, answers = command(["/usr/bin/dscacheutil", "-q", "host", "-a", "name", host], 3)
            if normal_peer in re.findall(r"^ip_address:\s*(\S+)\s*$", answers, re.M):
                pin = normal_peer
        return output, pin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="HTTPS site used for both probes")
    parser.add_argument("--address", type=ipaddress.IPv4Address,
                        help="previously verified address of that same site")
    parser.add_argument("--samples", type=int, default=6)
    parser.add_argument("--interval", type=float, default=2.0,
                        help="seconds between completed samples")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", args.host) or args.host.startswith("-"):
        parser.error("expected a hostname")
    if not 1 <= args.samples <= 3600 or not 1 <= args.interval <= 3600:
        parser.error("samples and interval must be within 1..3600")
    pin = str(args.address) if args.address else None
    for index in range(args.samples):
        result, pin = sample(args.host, pin)
        print(json.dumps(result, separators=(",", ":")), flush=True)
        if index + 1 < args.samples:
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
