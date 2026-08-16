import argparse
import asyncio
import concurrent.futures
import dataclasses
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import uac_desktop.engine as engine_mod
from uac_desktop.models import Tuning, default_profiles
from uac_desktop.pattern_core.core import PatternSniCore


OUTPUT = ROOT / "artifacts" / "mci_adaptive_scan"
PAIRS = (
    (1, "104.19.230.21"),
    (2, "104.24.133.30"),
    (3, "104.18.9.83"),
    (6, "104.16.1.1"),
)


class SplitPatternCore(PatternSniCore):
    def __init__(self, log, cut=0, delay_ms=0):
        super().__init__(log)
        self.scan_cut = max(0, int(cut))
        self.scan_delay = max(0, int(delay_ms)) / 1000

    async def _pump(self, source, destination, upload):
        loop = asyncio.get_running_loop()
        chunk_size = self._quality.relay_buffer_kb * 1024
        first = True
        while not self._stop.is_set():
            data = await loop.sock_recv(source, chunk_size)
            if not data:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return
            if upload and first and 0 < self.scan_cut < len(data):
                try:
                    destination.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                await loop.sock_sendall(destination, data[:self.scan_cut])
                if self.scan_delay:
                    await asyncio.sleep(self.scan_delay)
                await loop.sock_sendall(destination, data[self.scan_cut:])
            else:
                await loop.sock_sendall(destination, data)
            first = False
            if upload:
                self.upload += len(data)
            else:
                self.download += len(data)
            self._emit_traffic()


def wait_port(port, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                return True
        except OSError:
            time.sleep(0.04)
    return False


def request_one(proxy, name, url, minimum, timeout):
    started = time.perf_counter()
    result = {"name": name, "ok": False, "status": 0, "bytes": 0, "ms": 0, "error": ""}
    session = requests.Session()
    session.trust_env = False
    try:
        with session.get(
            url,
            proxies={"http": proxy, "https": proxy},
            stream=True,
            timeout=(timeout, timeout),
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0", "Accept-Encoding": "identity", "Connection": "close"},
        ) as response:
            result["status"] = response.status_code
            for chunk in response.iter_content(1024):
                if chunk:
                    result["bytes"] += len(chunk)
                if result["bytes"] >= minimum:
                    break
            result["ok"] = 200 <= response.status_code < 400 and result["bytes"] >= minimum
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        session.close()
    result["ms"] = round((time.perf_counter() - started) * 1000, 1)
    return result


def worker(profile_number, edge, offset, strategy, timeout, cut=0, delay_ms=0, quick=False, fake_sni="www.speedtest.net"):
    frag = 43043 + offset
    socks = 23008 + offset
    http = 24009 + offset
    engine_mod.SOCKS_PORT = socks
    engine_mod.HTTP_PORT = http
    original = default_profiles()[profile_number - 1]
    direct = strategy == "direct"
    endpoint = f"@{edge}:443" if direct else f"@127.0.0.1:{frag}"
    uri = original.source_uri.replace("@127.0.0.1:40443", endpoint)
    profile = dataclasses.replace(
        original,
        address=edge,
        config_host=edge if direct else "127.0.0.1",
        config_port=443 if direct else frag,
        source_uri=uri,
    )
    tuning = Tuning.carrier_preset("mci")
    tuning.pattern_connect_ip = edge
    tuning.pattern_fallback_ips = ""
    tuning.pattern_use_profile_edges = False
    tuning.pattern_fake_sni = fake_sni
    tuning.pattern_fake_repeat = 3
    tuning.pattern_inject_delay_ms = 15
    tuning.xray_mux_enabled = False
    tuning.pattern_max_sessions = 12
    core_logs = []
    core = SplitPatternCore(lambda line: core_logs.append(str(line)), cut, delay_ms)
    process = None
    config_path = Path(tempfile.gettempdir()) / f"uac-mci-raw-{profile_number}-{offset}.json"
    started = time.perf_counter()
    output = {
        "profile": profile.name,
        "edge": edge,
        "strategy": strategy,
        "fake_sni": tuning.pattern_fake_sni,
        "app_cut": cut,
        "app_delay_ms": delay_ms,
        "verified": False,
        "targets": [],
        "error": "",
    }
    try:
        if not direct:
            core.start(profile, tuning, strategy)
        config = engine_mod.build_xray_config(
            profile,
            tuning=tuning,
            upstream_address=None if direct else "127.0.0.1",
        )
        for inbound in config.get("inbounds", []):
            if inbound.get("protocol") == "http":
                inbound["port"] = http
            elif inbound.get("protocol") == "socks":
                inbound["port"] = socks
        config["log"] = {"loglevel": "warning"}
        config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        process = subprocess.Popen(
            [str(ROOT / "bin" / "xray.exe"), "run", "-config", str(config_path)],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if not wait_port(http):
            raise RuntimeError(f"Xray listener failed; exit={process.poll()}")
        proxy = f"http://127.0.0.1:{http}"
        targets = (("gstatic", "https://www.gstatic.com/generate_204", 0),) if quick else (
            ("gstatic", "https://www.gstatic.com/generate_204", 0),
            ("google", "https://www.google.com/robots.txt", 128),
            ("youtube", "https://www.youtube.com/generate_204", 0),
            ("ytimg", "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg", 512),
        )
        normalized = tuple((name, url, max(1, minimum), timeout) for name, url, minimum in targets)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            output["targets"] = list(pool.map(lambda args: request_one(proxy, *args), normalized))
        by_name = {item["name"]: item for item in output["targets"]}
        output["verified"] = by_name["gstatic"]["ok"] if quick else by_name["google"]["ok"] and by_name["ytimg"]["ok"]
    except Exception as exc:
        output["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        if process is not None and process.stdout is not None:
            try:
                output["xray_tail"] = process.stdout.read()[-2000:]
            except Exception:
                output["xray_tail"] = ""
        core.stop()
        config_path.unlink(missing_ok=True)
    output["active_edge"] = core.active_edge
    output["duration_ms"] = round((time.perf_counter() - started) * 1000, 1)
    output["core_tail"] = core_logs[-10:]
    return output


def parent(strategy, timeout):
    OUTPUT.mkdir(parents=True, exist_ok=True)
    processes = []
    for offset, (profile, edge) in enumerate(PAIRS):
        result_path = OUTPUT / f"runtime-{profile}.json"
        result_path.unlink(missing_ok=True)
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__)), "--worker", str(profile), edge, str(offset), "--strategy", strategy, "--timeout", str(timeout), "--result", str(result_path)],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        processes.append((profile, result_path, process))
    results = []
    for profile, result_path, process in processes:
        stdout, _ = process.communicate(timeout=max(30, timeout * 4))
        if result_path.exists():
            result = json.loads(result_path.read_text(encoding="utf-8"))
        else:
            result = {"profile": f"uacSpoofer {profile}", "verified": False, "error": stdout[-2000:]}
        results.append(result)
        print(json.dumps(result, ensure_ascii=False), flush=True)
    summary = {
        "strategy": strategy,
        "parallel_workers": len(PAIRS),
        "railway_used": False,
        "results": results,
        "winners": [item for item in results if item.get("verified")],
    }
    (OUTPUT / "runtime-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if summary["winners"] else 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", type=int)
    parser.add_argument("edge", nargs="?")
    parser.add_argument("offset", nargs="?", type=int)
    parser.add_argument("--strategy", default="tls_sni_records")
    parser.add_argument("--timeout", type=float, default=6)
    parser.add_argument("--result")
    parser.add_argument("--cut", type=int, default=0)
    parser.add_argument("--delay-ms", type=int, default=0)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--fake-sni", default="www.speedtest.net")
    args = parser.parse_args()
    if args.worker:
        result = worker(
            args.worker, args.edge, args.offset, args.strategy, args.timeout,
            args.cut, args.delay_ms, args.quick, args.fake_sni,
        )
        Path(args.result).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        return 0 if result["verified"] else 2
    return parent(args.strategy, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
