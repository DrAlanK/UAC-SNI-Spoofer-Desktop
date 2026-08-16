import argparse
import base64
import concurrent.futures
import csv
import ctypes
import itertools
import json
import os
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from uac_desktop.engine import build_xray_config
from uac_desktop.models import Tuning, default_profiles, parse_outbound
from uac_desktop.pattern_core.core import PatternSniCore


PROFILE_IDS = (1, 2, 3, 4, 5, 6)
EDGES = ("104.18.8.83", "104.19.229.21")
FAKE_SNIS = (
    "community.cloudflare.com",
    "assets.cloudflare.com",
    "www.hcaptcha.com",
    "chatgpt.com",
    "workers.dev",
    "cdn.jsdelivr.net",
    "www.cloudflare.com",
    "support.cloudflare.com",
    "api.cloudflare.com",
    "radar.cloudflare.com",
)
STRATEGIES = ("wrong_seq", "full5")
CSV_FIELDS = (
    "kind", "profile", "profile_name", "edge", "strategy", "fake_sni",
    "repeat", "delay_ms", "tls_ok", "upgrade_ok", "status", "elapsed_ms",
    "google_ok", "youtube_ok", "verified", "error",
)


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate():
    if os.name != "nt":
        raise SystemExit("Windows is required.")
    if is_admin():
        return
    params = subprocess.list2cmdline([str(Path(__file__).resolve()), *sys.argv[1:]])
    code = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, str(ROOT), 1
    )
    if code <= 32:
        raise SystemExit(f"Elevation failed: ShellExecute={code}")
    raise SystemExit(0)


def atomic_json(path, data):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def append_result(jsonl_path, csv_path, entry):
    with jsonl_path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    fresh = not csv_path.exists() or csv_path.stat().st_size == 0
    with csv_path.open("a", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        if fresh:
            writer.writeheader()
        writer.writerow({key: entry.get(key, "") for key in CSV_FIELDS})
        stream.flush()
        os.fsync(stream.fileno())


def make_tuning(edge, fake_sni, repeat, delay_ms):
    tuning = Tuning.carrier_preset("mci")
    tuning.pattern_connect_ip = edge
    tuning.pattern_fallback_ips = ""
    tuning.pattern_use_profile_edges = False
    tuning.pattern_fake_sni = fake_sni
    tuning.pattern_fake_repeat = repeat
    tuning.pattern_inject_delay_ms = delay_ms
    tuning.log_level = "minimal"
    return tuning


def edge_preflight(edge, timeout):
    started = time.perf_counter()
    try:
        with socket.create_connection((edge, 443), timeout=timeout):
            return {"edge": edge, "reachable": True,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                    "error": ""}
    except Exception as exc:
        return {"edge": edge, "reachable": False,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                "error": f"{type(exc).__name__}: {exc}"}


def raw_upgrade(profile, tuning, strategy, timeout):
    parsed = parse_outbound(profile)
    logs = []
    core = PatternSniCore(lambda line: logs.append(str(line)))
    tls_sock = None
    started = time.perf_counter()
    result = {"tls_ok": False, "upgrade_ok": False, "status": "",
              "elapsed_ms": None, "error": "", "response_head": "", "core_tail": []}
    try:
        core.start(profile, tuning, strategy)
        raw_sock = socket.create_connection(("127.0.0.1", profile.config_port), timeout=timeout)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["http/1.1"])
        tls_sock = context.wrap_socket(raw_sock, server_hostname=parsed["sni"])
        result["tls_ok"] = True
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {parsed['path']} HTTP/1.1\r\n"
            f"Host: {parsed['host_header']}\r\n"
            "Connection: Upgrade\r\nUpgrade: websocket\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            "User-Agent: UAC-MCI-Probe/1.0\r\n\r\n"
        ).encode("ascii", "strict")
        tls_sock.settimeout(timeout)
        tls_sock.sendall(request)
        response = tls_sock.recv(4096)
        head = response.decode("iso-8859-1", "replace")
        result["response_head"] = head[:256]
        result["status"] = head.split("\r\n", 1)[0] if head else "empty"
        result["upgrade_ok"] = result["status"].startswith("HTTP/1.1 101")
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if tls_sock is not None:
            try:
                tls_sock.close()
            except OSError:
                pass
        core.stop()
        result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 1)
        result["core_tail"] = logs[-5:]
    return result


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(port, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def fetch_target(proxy, target, timeout):
    name, url, minimum = target
    started = time.perf_counter()
    result = {"name": name, "ok": False, "status": None, "bytes": 0, "error": ""}
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.get(
                url, proxies={"http": proxy, "https": proxy}, stream=True,
                timeout=(timeout, timeout), allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0", "Accept-Encoding": "identity",
                         "Cache-Control": "no-cache", "Connection": "close"},
            )
            try:
                data = b""
                for chunk in response.iter_content(512):
                    if chunk:
                        data += chunk
                    if len(data) >= minimum:
                        break
                result["status"] = response.status_code
                result["bytes"] = len(data)
                result["ok"] = 200 <= response.status_code < 400 and len(data) >= minimum
            finally:
                response.close()
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return result


def xray_web_test(profile, tuning, strategy, timeout, work_dir):
    core = PatternSniCore(lambda _line: None)
    process = None
    http_port = free_port()
    socks_port = free_port()
    config_path = work_dir / "mci-fake-sni-xray.json"
    output = {"google_ok": False, "youtube_ok": False, "verified": False,
              "targets": [], "error": "", "xray_tail": ""}
    try:
        core.start(profile, tuning, strategy)
        config = build_xray_config(profile, tuning=tuning, upstream_address="127.0.0.1")
        for inbound in config.get("inbounds", []):
            if inbound.get("protocol") == "http":
                inbound["port"] = http_port
            elif inbound.get("protocol") == "socks":
                inbound["port"] = socks_port
        config["log"] = {"loglevel": "warning"}
        config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        process = subprocess.Popen(
            [str(ROOT / "bin" / "xray.exe"), "run", "-config", str(config_path)],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if not wait_port(http_port):
            raise RuntimeError(f"Xray HTTP listener did not open; exit={process.poll()}")
        proxy = f"http://127.0.0.1:{http_port}"
        targets = (
            ("google", "https://www.google.com/robots.txt", 128),
            ("youtube", "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg", 512),
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            output["targets"] = list(executor.map(
                lambda target: fetch_target(proxy, target, timeout), targets
            ))
        for item in output["targets"]:
            output[f"{item['name']}_ok"] = item["ok"]
        output["verified"] = output["google_ok"] and output["youtube_ok"]
    except Exception as exc:
        output["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        stop_process(process)
        if process is not None and process.stdout is not None:
            try:
                output["xray_tail"] = process.stdout.read()[-1500:]
            except Exception:
                pass
        core.stop()
        config_path.unlink(missing_ok=True)
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-timeout", type=float, default=2.5)
    parser.add_argument("--web-timeout", type=float, default=8.0)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--delay-ms", type=int, default=15)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--output-prefix", default=str(Path(__file__).with_suffix("")))
    args = parser.parse_args()
    elevate()

    profiles = tuple(profile for profile in default_profiles() if profile.origin == "builtin")[:6]
    if len(profiles) != 6:
        raise SystemExit(f"Expected 6 builtin Suggested profiles, found {len(profiles)}")
    if not (ROOT / "bin" / "xray.exe").exists():
        raise SystemExit("Missing bin/xray.exe")

    prefix = Path(args.output_prefix).resolve()
    prefix.parent.mkdir(parents=True, exist_ok=True)
    jsonl_path = prefix.with_name(prefix.name + "_results.jsonl")
    csv_path = prefix.with_name(prefix.name + "_results.csv")
    summary_path = prefix.with_name(prefix.name + "_summary.json")
    jsonl_path.unlink(missing_ok=True)
    csv_path.unlink(missing_ok=True)

    workers = max(1, min(32, args.workers))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        preflight = list(executor.map(
            lambda edge: edge_preflight(edge, min(args.raw_timeout, 1.5)), EDGES
        ))
    edges = tuple(item["edge"] for item in preflight if item["reachable"])
    report = {
        "started_at": now_iso(), "finished_at": None,
        "profiles": list(PROFILE_IDS), "edges": list(EDGES),
        "reachable_edges": list(edges), "fake_snis": list(FAKE_SNIS),
        "strategies": list(STRATEGIES), "preflight": preflight,
        "preflight_workers": workers, "pattern_workers": 1,
        "raw_attempts": 0, "upgrade_candidates": 0, "xray_attempts": 0,
        "winner": None,
        "files": {"jsonl": str(jsonl_path), "csv": str(csv_path),
                  "summary": str(summary_path)},
    }
    atomic_json(summary_path, report)
    if not edges:
        report["finished_at"] = now_iso()
        report["error"] = "No configured edge accepted TCP/443."
        atomic_json(summary_path, report)
        return 2

    combinations = itertools.product(PROFILE_IDS, edges, FAKE_SNIS, STRATEGIES)
    total = len(PROFILE_IDS) * len(edges) * len(FAKE_SNIS) * len(STRATEGIES)
    try:
        for number, (profile_id, edge, fake_sni, strategy) in enumerate(combinations, 1):
            profile = profiles[profile_id - 1]
            tuning = make_tuning(edge, fake_sni, args.repeat, args.delay_ms)
            identity = {"profile": profile_id, "profile_name": profile.name,
                        "edge": edge, "strategy": strategy, "fake_sni": fake_sni,
                        "repeat": args.repeat, "delay_ms": args.delay_ms}
            print(f"[{number}/{total}] {json.dumps(identity, ensure_ascii=False)}", flush=True)
            raw = {"kind": "raw", **identity,
                   **raw_upgrade(profile, tuning, strategy, args.raw_timeout)}
            append_result(jsonl_path, csv_path, raw)
            report["raw_attempts"] += 1
            if raw["upgrade_ok"]:
                report["upgrade_candidates"] += 1
                web = {"kind": "xray", **identity,
                       **xray_web_test(profile, tuning, strategy,
                                       args.web_timeout, summary_path.parent)}
                append_result(jsonl_path, csv_path, web)
                report["xray_attempts"] += 1
                if web["verified"]:
                    report["winner"] = web
                    atomic_json(summary_path, report)
                    print("VERIFIED WINNER " + json.dumps(identity, ensure_ascii=False), flush=True)
                    break
            atomic_json(summary_path, report)
    except KeyboardInterrupt:
        report["interrupted"] = True
    finally:
        report["finished_at"] = now_iso()
        atomic_json(summary_path, report)
        print(f"JSONL: {jsonl_path}", flush=True)
        print(f"CSV: {csv_path}", flush=True)
        print(f"Summary: {summary_path}", flush=True)
        print("Winner: " + json.dumps(report["winner"], ensure_ascii=False), flush=True)
    return 0 if report["winner"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
