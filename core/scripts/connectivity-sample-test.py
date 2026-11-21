"""Check the sampler's DNS/IP distinction without opening a network connection."""
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

script = Path(__file__).resolve().parents[2] / "scripts/sample-connectivity.py"
spec = importlib.util.spec_from_file_location("connectivity_sample", script)
sampler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sampler)
host, ip = "site.example", "192.0.2.1"


def with_network(normal, fixed, loopback=True, resolver_ip=ip):
    def invoke(args, timeout):
        tool = Path(args[0]).name
        if tool == "curl":
            return fixed if "--resolve" in args else normal
        if tool == "scutil":
            return 0, " nameserver[0] : 127.0.0.1\n" if loopback else ""
        if tool == "dig":
            assert loopback and args[1] == "@127.0.0.1"
            return 9, ";; no servers could be reached\n"
        if tool == "route":
            return 0, "interface: utun9\n"
        if tool == "dscacheutil":
            return 0, "ip_address: " + resolver_ip + "\n"
        raise AssertionError(tool)
    return patch.object(sampler, "command", invoke)


success = (0, f"200 0.00001 0.2 {ip}")
failure = (6, "000 0.0 0.0 ")
with with_network(failure, success):
    row, pin = sampler.sample(host, ip)
    assert row["normal"]["exit"] == 6 and row["pinned"]["reachedPin"]
    assert row["pinned"]["http"] == 200 and row["pinned"]["sameNormalPeer"] is None
    assert all(o["status"] == "no-response" for o in row["localDNS"].values())
    assert host not in json.dumps(row) and ip not in json.dumps(row)

with with_network(success, success, loopback=False):
    first, pin = sampler.sample(host, None)
    assert pin == ip and "pinned" not in first and not first["localDNS"]
    second, _ = sampler.sample(host, pin)
    assert second["pinned"]["sameNormalPeer"]

with with_network(success, success, resolver_ip="192.0.2.9"):
    _, pin = sampler.sample(host, None)
    assert pin is None, "a proxy or stale peer must not become the site's reference IP"
print("PASS paired HTTPS, local DNS, pin selection and output redaction")
