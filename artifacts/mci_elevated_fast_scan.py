import csv
import ctypes
import json
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mci_raw_runtime_probe import worker


OUTPUT = ROOT / "artifacts" / "mci_adaptive_scan"
JSONL = OUTPUT / "elevated-results.jsonl"
CSV = OUTPUT / "elevated-results.csv"
SUMMARY = OUTPUT / "elevated-summary.json"
PROGRESS = OUTPUT / "elevated-progress.log"
PRIMARY = (
    (1, "104.19.230.21"),
    (2, "104.24.133.30"),
    (3, "104.18.9.83"),
    (6, "104.16.1.1"),
)
ALTERNATES = (
    (1, "188.114.97.2"), (1, "104.25.122.225"),
    (2, "188.114.97.2"), (2, "190.93.245.235"),
    (3, "172.66.0.1"), (3, "188.114.99.0"),
    (3, "104.18.1.1"), (3, "198.41.206.20"),
    (6, "172.66.0.1"), (6, "104.17.10.61"),
)
FAKES = (
    "www.speedtest.net",
    "community.cloudflare.com",
    "www.hcaptcha.com",
    "support.cloudflare.com",
)


def plans():
    values = []
    for strategy in ("full5", "wrong_seq"):
        for profile, edge in PRIMARY:
            values.append((profile, edge, strategy, FAKES[0], 0, 0))
    for fake in FAKES[1:]:
        for strategy in ("full5", "wrong_seq"):
            for profile, edge in PRIMARY:
                values.append((profile, edge, strategy, fake, 0, 0))
    for strategy in ("full5", "wrong_seq"):
        for profile, edge in ALTERNATES:
            values.append((profile, edge, strategy, FAKES[0], 0, 0))
    for cut, delay in ((17, 3), (37, 8), (5, 15)):
        for strategy in ("full5", "wrong_seq"):
            for profile, edge in PRIMARY:
                values.append((profile, edge, strategy, FAKES[0], cut, delay))
    return values


def write_summary(data):
    temp = SUMMARY.with_suffix(".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(SUMMARY)


def append_result(entry):
    with JSONL.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
    flat = {
        "profile": entry.get("profile", ""),
        "edge": entry.get("edge", ""),
        "strategy": entry.get("strategy", ""),
        "fake_sni": entry.get("fake_sni", ""),
        "app_cut": entry.get("app_cut", 0),
        "app_delay_ms": entry.get("app_delay_ms", 0),
        "verified": entry.get("verified", False),
        "duration_ms": entry.get("duration_ms", 0),
        "error": entry.get("error", ""),
        "targets": json.dumps(entry.get("targets", []), ensure_ascii=False),
    }
    fresh = not CSV.exists()
    with CSV.open("a", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=flat)
        if fresh:
            writer.writeheader()
        writer.writerow(flat)


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    if not ctypes.windll.shell32.IsUserAnAdmin():
        PROGRESS.write_text("Administrator access is required", encoding="utf-8")
        return 5
    for path in (JSONL, CSV, SUMMARY, PROGRESS):
        path.unlink(missing_ok=True)
    matrix = plans()
    report = {
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "finished_at": None,
        "total_plans": len(matrix),
        "attempts": 0,
        "railway_used": False,
        "winner": None,
    }
    write_summary(report)
    started = time.perf_counter()
    for index, (profile, edge, strategy, fake, cut, delay) in enumerate(matrix):
        line = f"{index + 1}/{len(matrix)} profile={profile} edge={edge} strategy={strategy} fake={fake} cut={cut} delay={delay}"
        PROGRESS.write_text(line, encoding="utf-8")
        quick = worker(profile, edge, 300 + index, strategy, 5.5, cut, delay, True, fake)
        quick["phase"] = "quick"
        append_result(quick)
        report["attempts"] += 1
        write_summary(report)
        if not quick.get("verified"):
            continue
        full = worker(profile, edge, 700 + index, strategy, 12, cut, delay, False, fake)
        full["phase"] = "full"
        append_result(full)
        report["attempts"] += 1
        if full.get("verified"):
            report["winner"] = full
            break
    report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    report["duration_s"] = round(time.perf_counter() - started, 2)
    write_summary(report)
    PROGRESS.write_text("DONE " + json.dumps(report["winner"], ensure_ascii=False), encoding="utf-8")
    return 0 if report["winner"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
