import concurrent.futures
import csv
import dataclasses
import json
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from uac_desktop.engine import build_xray_config
from uac_desktop.models import Tuning, default_profiles


OUTPUT = ROOT / "artifacts" / "mci_patterniha_scan"
KNOWN_PAIRS = (
    (1, "104.19.230.21"),
    (1, "188.114.97.2"),
    (1, "104.25.122.225"),
    (2, "104.24.133.30"),
    (2, "188.114.97.2"),
    (2, "190.93.245.235"),
    (3, "104.18.9.83"),
    (3, "172.66.0.1"),
    (3, "188.114.99.0"),
    (3, "104.18.1.1"),
    (3, "198.41.206.20"),
    (6, "104.16.1.1"),
    (6, "172.66.0.1"),
    (6, "104.17.10.61"),
)
HIGH_DELAYS = [1] * 9 + [400] + [1] * 9 + [400] + [1] * 9 + [400] + [1]
VARIANTS = {
    "v48-low": [
        {"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5", "1"], "delays": ["0"], "maxSplit": "0"}},
        {"type": "fragment", "settings": {"packets": "1-1", "lengths": ["43", "1"], "delays": ["1"], "maxSplit": "522"}},
    ],
    "v48-high": [
        {"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5", "1"], "delays": ["0"], "maxSplit": "0"}},
        {"type": "fragment", "settings": {"packets": "1-1", "lengths": ["43", "1"], "delays": [str(v) for v in HIGH_DELAYS], "maxSplit": "522"}},
    ],
    "v46-low": [
        {"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["6", "1"], "delays": ["0"], "maxSplit": "0"}},
        {"type": "fragment", "settings": {"packets": "1-1", "lengths": ["1"], "delays": ["1"], "maxSplit": "923"}},
    ],
    "v46-high": [
        {"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["6", "1"], "delays": ["0"], "maxSplit": "0"}},
        {"type": "fragment", "settings": {"packets": "1-1", "lengths": ["1"], "delays": [str(v) for v in HIGH_DELAYS], "maxSplit": "923"}},
    ],
    "v47": [
        {"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5"], "delays": ["0"], "maxSplit": "2"}},
    ],
}


def xray_version(path):
    try:
        line = subprocess.check_output([str(path), "version"], text=True, errors="replace", timeout=4).splitlines()[0]
        match = re.search(r"Xray\s+(\d+)\.(\d+)\.(\d+)", line)
        return tuple(map(int, match.groups())) if match else (0, 0, 0)
    except Exception:
        return (0, 0, 0)


def select_xray():
    candidates = list((ROOT / "bin").glob("**/xray.exe"))
    ranked = sorted(((xray_version(path), path) for path in candidates), reverse=True)
    if not ranked or ranked[0][0] < (26, 6, 27):
        raise RuntimeError("Xray 26.6.27 or newer is required for the Patterniha Finalmask schema")
    return ranked[0][1], ranked[0][0]


def wait_port(port, process, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.12):
                return True
        except OSError:
            time.sleep(0.03)
    return False


def fetch(proxy, name, url, minimum, timeout):
    started = time.perf_counter()
    result = {"name": name, "ok": False, "status": 0, "bytes": 0, "ms": 0.0, "error": ""}
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
            result["status"] = int(response.status_code)
            for chunk in response.iter_content(2048):
                if chunk:
                    result["bytes"] += len(chunk)
                if minimum and result["bytes"] >= minimum:
                    break
            result["ok"] = 200 <= result["status"] < 400 and (minimum == 0 or result["bytes"] >= minimum)
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        session.close()
    result["ms"] = round((time.perf_counter() - started) * 1000, 1)
    return result


def direct_profile(profile_number, edge, edge_port):
    original = default_profiles()[profile_number - 1]
    uri = re.sub(r"@127\.0\.0\.1:40443", f"@{edge}:{edge_port}", original.source_uri, count=1)
    return dataclasses.replace(
        original,
        address=edge,
        port=edge_port,
        config_host=edge,
        config_port=edge_port,
        source_uri=uri,
    )


def build_config(profile_number, edge, edge_port, variant, fingerprint, http_port, socks_port):
    profile = direct_profile(profile_number, edge, edge_port)
    tuning = Tuning.carrier_preset("mci")
    tuning.xray_mux_enabled = False
    config = build_xray_config(profile, tuning=tuning)
    for inbound in config["inbounds"]:
        inbound["port"] = socks_port if inbound["protocol"] == "socks" else http_port
    outbound = config["outbounds"][0]
    stream = outbound["streamSettings"]
    stream["finalmask"] = {"tcp": VARIANTS[variant]}
    tls = stream.get("tlsSettings", {})
    tls["fingerprint"] = fingerprint
    tls["alpn"] = ["http/1.1"]
    stream["sockopt"] = {
        "domainStrategy": "UseIPv4",
        "tcpKeepAliveInterval": 1,
        "tcpKeepAliveIdle": 11,
    }
    config["log"] = {"loglevel": "warning"}
    return config, profile


def run_case(case, xray_path, timeout, full=False):
    index = case["index"]
    http_port = 32000 + index
    socks_port = 35000 + index
    config, profile = build_config(
        case["profile"], case["edge"], case["port"], case["variant"], case["fingerprint"], http_port, socks_port
    )
    config_path = Path(tempfile.gettempdir()) / f"uac-mci-finalmask-{index}.json"
    config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
    process = None
    started = time.perf_counter()
    result = dict(case)
    result.update({"profile_name": profile.name, "verified": False, "targets": [], "error": "", "xray_tail": ""})
    try:
        process = subprocess.Popen(
            [str(xray_path), "run", "-config", str(config_path)],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if not wait_port(http_port, process):
            raise RuntimeError(f"Xray listener failed; exit={process.poll()}")
        proxy = f"http://127.0.0.1:{http_port}"
        targets = (
            ("gstatic", "https://www.gstatic.com/generate_204", 0),
        ) if not full else (
            ("gstatic", "https://www.gstatic.com/generate_204", 0),
            ("google", "https://www.google.com/robots.txt", 128),
            ("youtube", "https://www.youtube.com/generate_204", 0),
            ("ytimg", "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg", 512),
        )
        for name, url, minimum in targets:
            target = fetch(proxy, name, url, minimum, timeout)
            result["targets"].append(target)
            if not target["ok"] and not full:
                break
        by_name = {item["name"]: item for item in result["targets"]}
        result["verified"] = by_name.get("gstatic", {}).get("ok", False) if not full else all(
            by_name.get(name, {}).get("ok", False) for name in ("google", "youtube", "ytimg")
        )
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=1.5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1.5)
            if process.stdout is not None:
                try:
                    result["xray_tail"] = process.stdout.read()[-1600:]
                except Exception:
                    pass
        config_path.unlink(missing_ok=True)
    result["duration_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return result


def run_matrix(cases, xray_path, workers, timeout, stage, full=False):
    print(f"STAGE {stage}: {len(cases)} cases, workers={workers}, timeout={timeout}s", flush=True)
    started = time.perf_counter()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(run_case, case, xray_path, timeout, full): case for case in cases}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            result["stage"] = stage
            results.append(result)
            done += 1
            if result["verified"]:
                print(
                    f"WIN {stage} p{result['profile']} {result['edge']}:{result['port']} {result['variant']} {result['fingerprint']}",
                    flush=True,
                )
            elif done % max(1, len(cases) // 5) == 0:
                print(f"PROGRESS {stage} {done}/{len(cases)}", flush=True)
    print(f"DONE {stage}: winners={sum(bool(r['verified']) for r in results)} elapsed={time.perf_counter()-started:.1f}s", flush=True)
    return results


def save(results, xray_path, xray_ver):
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    fields = ["stage", "profile", "profile_name", "edge", "port", "variant", "fingerprint", "verified", "duration_ms", "error"]
    with (OUTPUT / "results.csv").open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in results:
            writer.writerow({key: item.get(key, "") for key in fields})
    winners = [item for item in results if item.get("verified")]
    summary = {
        "xray": str(xray_path),
        "xray_version": ".".join(map(str, xray_ver)),
        "ipv6_tested": False,
        "railway_used": False,
        "upstream_replaced": False,
        "cases": len(results),
        "winners": len(winners),
        "healthy_routes": winners,
    }
    (OUTPUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    xray_path, xray_ver = select_xray()
    print(f"XRAY {xray_path} version={'.'.join(map(str, xray_ver))}", flush=True)
    all_results = []
    next_index = 0
    primary = []
    for profile, edge in KNOWN_PAIRS:
        for variant in VARIANTS:
            primary.append({"index": next_index, "profile": profile, "edge": edge, "port": 443, "variant": variant, "fingerprint": "chrome"})
            next_index += 1
    first = run_matrix(primary, xray_path, 24, 6.0, "pattern-history")
    all_results.extend(first)
    quick_winners = [item for item in first if item["verified"]]
    if not quick_winners:
        fingerprints = []
        for profile, edge in KNOWN_PAIRS:
            for variant in ("v48-low", "v46-low"):
                for fingerprint in ("firefox", "randomized"):
                    fingerprints.append({"index": next_index, "profile": profile, "edge": edge, "port": 443, "variant": variant, "fingerprint": fingerprint})
                    next_index += 1
        second = run_matrix(fingerprints, xray_path, 24, 6.0, "fingerprints")
        all_results.extend(second)
        quick_winners.extend(item for item in second if item["verified"])
    if not quick_winners:
        ports = []
        for profile, edge in KNOWN_PAIRS:
            for edge_port in (2053, 2083, 2087, 2096, 8443):
                for variant in ("v48-low", "v46-low"):
                    ports.append({"index": next_index, "profile": profile, "edge": edge, "port": edge_port, "variant": variant, "fingerprint": "chrome"})
                    next_index += 1
        third = run_matrix(ports, xray_path, 32, 5.0, "alternate-ports")
        all_results.extend(third)
        quick_winners.extend(item for item in third if item["verified"])
    full_results = []
    if quick_winners:
        finalists = []
        for winner in quick_winners:
            item = {key: winner[key] for key in ("profile", "edge", "port", "variant", "fingerprint")}
            item["index"] = next_index
            next_index += 1
            finalists.append(item)
        full_results = run_matrix(finalists, xray_path, min(8, len(finalists)), 12.0, "full-validation", full=True)
        all_results.extend(full_results)
    summary = save(all_results, xray_path, xray_ver)
    print(json.dumps({"cases": summary["cases"], "winners": summary["winners"], "output": str(OUTPUT)}, ensure_ascii=False), flush=True)
    return 0 if any(item.get("verified") and item.get("stage") == "full-validation" for item in all_results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
