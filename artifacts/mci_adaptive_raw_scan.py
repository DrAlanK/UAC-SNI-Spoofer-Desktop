import asyncio
import base64
import csv
import ipaddress
import json
import os
import ssl
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from uac_desktop.models import default_profiles, parse_outbound


OUTPUT = ROOT / "artifacts" / "mci_adaptive_scan"
OUTPUT.mkdir(parents=True, exist_ok=True)
JSONL = OUTPUT / "raw-results.jsonl"
CSV = OUTPUT / "results.csv"
SUMMARY = OUTPUT / "summary.json"
KNOWN = (
    "104.18.8.83", "104.18.9.83", "104.18.32.47", "188.114.99.0",
    "104.19.229.21", "104.19.230.21", "104.18.22.63", "104.18.23.63",
    "104.18.0.55", "104.18.1.55", "104.18.10.110", "104.18.11.110",
    "104.16.1.1", "104.18.1.1", "104.16.0.1", "104.16.2.1",
    "188.114.97.2", "188.114.96.2", "104.18.2.1", "104.20.0.1",
    "104.19.0.1", "172.66.0.1", "172.67.0.1", "162.159.192.1",
    "162.159.193.1", "172.64.0.1", "172.65.0.1", "188.114.98.0",
)
RANGES = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)


def candidates():
    values = list(KNOWN)
    for raw in RANGES:
        network = ipaddress.ip_network(raw)
        span = int(network.num_addresses)
        for ratio in (0.13, 0.37, 0.61, 0.87):
            offset = max(1, min(span - 2, int(span * ratio)))
            values.append(str(network.network_address + offset))
    return tuple(dict.fromkeys(values))


async def probe(profile, edge, timeout, semaphore):
    parsed = parse_outbound(profile)
    started = time.perf_counter()
    result = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "profile": profile.name,
        "edge": edge,
        "sni": parsed["sni"],
        "host": parsed["host_header"],
        "path": parsed["path"],
        "transport": parsed["network"],
        "tcp_ok": False,
        "tls_ok": False,
        "upgrade_ok": False,
        "status": "",
        "elapsed_ms": 0,
        "error": "",
    }
    writer = None
    async with semaphore:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(["http/1.1"])
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(edge, 443, ssl=context, server_hostname=parsed["sni"]),
                timeout,
            )
            result["tcp_ok"] = True
            result["tls_ok"] = True
            key = base64.b64encode(os.urandom(16)).decode("ascii")
            request = (
                f"GET {parsed['path']} HTTP/1.1\r\n"
                f"Host: {parsed['host_header']}\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "User-Agent: UAC-MCI-Adaptive-Scan/1.0\r\n\r\n"
            ).encode("ascii", "strict")
            writer.write(request)
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
            status = head.decode("iso-8859-1", "replace").split("\r\n", 1)[0]
            result["status"] = status
            result["upgrade_ok"] = status.startswith("HTTP/1.1 101")
        except asyncio.IncompleteReadError as exc:
            raw = exc.partial.decode("iso-8859-1", "replace")
            result["status"] = raw.split("\r\n", 1)[0] if raw else "empty"
            result["error"] = "IncompleteReadError"
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return result


async def main():
    profiles = tuple(profile for profile in default_profiles() if profile.origin == "builtin")[:6]
    edges = candidates()
    timeout = 2.25
    semaphore = asyncio.Semaphore(96)
    JSONL.unlink(missing_ok=True)
    CSV.unlink(missing_ok=True)
    started = time.perf_counter()
    tasks = [asyncio.create_task(probe(profile, edge, timeout, semaphore)) for profile in profiles for edge in edges]
    results = []
    completed = 0
    for task in asyncio.as_completed(tasks):
        item = await task
        results.append(item)
        completed += 1
        if completed % 50 == 0 or item["upgrade_ok"]:
            print(f"{completed}/{len(tasks)} upgrade={item['upgrade_ok']} {item['profile']} {item['edge']} {item['status']}", flush=True)
    fields = tuple(results[0]) if results else ()
    with JSONL.open("w", encoding="utf-8", newline="\n") as stream:
        for item in results:
            stream.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
    with CSV.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)
    upgrades = sorted((item for item in results if item["upgrade_ok"]), key=lambda item: item["elapsed_ms"])
    statuses = {}
    for item in results:
        statuses[item["status"] or item["error"].split(":", 1)[0]] = statuses.get(item["status"] or item["error"].split(":", 1)[0], 0) + 1
    summary = {
        "profiles": len(profiles),
        "edges": len(edges),
        "attempts": len(results),
        "workers": 96,
        "timeout_s": timeout,
        "duration_s": round(time.perf_counter() - started, 2),
        "tls_ok": sum(item["tls_ok"] for item in results),
        "upgrade_101": len(upgrades),
        "statuses": statuses,
        "winners": upgrades,
        "railway_used": False,
    }
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
