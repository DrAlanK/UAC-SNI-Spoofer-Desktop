import concurrent.futures
import json
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "artifacts" / "mci_raw_runtime_probe.py"
OUTPUT = ROOT / "artifacts" / "mci_adaptive_scan"
PAIRS = (
    (1, "104.19.230.21"),
    (2, "104.24.133.30"),
    (3, "104.18.9.83"),
    (6, "104.16.1.1"),
)
CUTS = (1, 5, 17, 37, 73)
DELAYS = (1, 3, 8, 15)


def attempt(item):
    index, profile, edge, cut, delay = item
    result_path = OUTPUT / f"split-{index}.json"
    result_path.unlink(missing_ok=True)
    command = [
        sys.executable, str(SCRIPT), "--worker", str(profile), edge, str(index),
        "--strategy", "full20", "--timeout", "4.5", "--cut", str(cut),
        "--delay-ms", str(delay), "--quick", "--result", str(result_path),
    ]
    completed = subprocess.run(
        command, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", timeout=25,
    )
    if result_path.exists():
        result = json.loads(result_path.read_text(encoding="utf-8"))
    else:
        result = {
            "profile": f"uacSpoofer {profile}", "edge": edge,
            "app_cut": cut, "app_delay_ms": delay, "verified": False,
            "error": completed.stdout[-1000:],
        }
    result["worker_exit"] = completed.returncode
    return result


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    items = []
    for profile, edge in PAIRS:
        for cut in CUTS:
            for delay in DELAYS:
                items.append((len(items), profile, edge, cut, delay))
    started = time.perf_counter()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(attempt, item) for item in items]
        for number, future in enumerate(concurrent.futures.as_completed(futures), 1):
            result = future.result()
            results.append(result)
            if number % 8 == 0 or result.get("verified"):
                print(
                    f"{number}/{len(items)} winner={result.get('verified')} "
                    f"{result.get('profile')} cut={result.get('app_cut')} delay={result.get('app_delay_ms')}",
                    flush=True,
                )
    winners = [item for item in results if item.get("verified")]
    summary = {
        "attempts": len(results), "workers": 8,
        "duration_s": round(time.perf_counter() - started, 2),
        "railway_used": False, "winners": winners, "results": results,
    }
    (OUTPUT / "app-split-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps({key: summary[key] for key in ("attempts", "workers", "duration_s", "railway_used", "winners")}, ensure_ascii=False), flush=True)
    return 0 if winners else 2


if __name__ == "__main__":
    raise SystemExit(main())
