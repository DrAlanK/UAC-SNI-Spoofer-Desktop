#!/usr/bin/env python3
"""Standalone Tor + WebTunnel test — no UI, no build required.

Usage (Windows PowerShell)::

    # Interactive: paste bridge lines when prompted
    python tools\\test_tor.py

    # Non-interactive: pass a file with one bridge per line
    python tools\\test_tor.py bridges.txt

    # Non-interactive: pipe bridges via stdin
    Get-Content bridges.txt | python tools\\test_tor.py -

The script:
  1. Reads bridge lines (WebTunnel / obfs4 / snowflake / meek_lite).
  2. Spawns Tor with those bridges.
  3. Waits for SOCKS + full bootstrap.
  4. Queries check.torproject.org for the exit IP.
  5. Prints a clear OK/FAIL summary and exits 0/1.

No changes to the codebase are required to run this.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Make "uac_desktop" importable when the script is run from the repo root
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from uac_desktop.tor_manager import (  # noqa: E402
    TorError,
    TorManager,
    parse_bridge_line,
)


BANNER = "=" * 70


def _read_bridges(argv: list[str]) -> list[str]:
    """Read bridge lines from a file, stdin, or interactive prompt."""
    # Case 1: file argument
    if len(argv) >= 2 and argv[1] != "-":
        path = Path(argv[1])
        if not path.is_file():
            print(f"[error] file not found: {path}")
            sys.exit(2)
        print(f"[input] reading bridges from {path}")
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    # Case 2: stdin (piped or "-")
    if len(argv) >= 2 and argv[1] == "-":
        print("[input] reading bridges from stdin")
        return [
            line.strip()
            for line in sys.stdin.read().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    # Case 3: interactive
    print()
    print(BANNER)
    print("Paste WebTunnel bridge lines below, one per line.")
    print("Get fresh bridges from: https://bridges.torproject.org/")
    print("Choose the 'WebTunnel' transport.")
    print(BANNER)
    print("When you're done, press Ctrl+Z then Enter (Windows) or")
    print("Ctrl+D (Linux/macOS) to start Tor.")
    print(BANNER)
    print()
    lines = []
    try:
        while True:
            raw = input()
            lines.append(raw)
    except EOFError:
        pass
    return [
        line.strip()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _validate(lines: list[str]) -> list[str]:
    """Parse each line and drop invalid ones, reporting what was found."""
    valid: list[str] = []
    print()
    print(f"[parse] checking {len(lines)} line(s)...")
    for index, line in enumerate(lines, 1):
        bridge = parse_bridge_line(line)
        if bridge is None:
            print(f"  [{index}] INVALID: {line[:80]}{'...' if len(line) > 80 else ''}")
            continue
        valid.append(line)
        fp = bridge.fingerprint[:16] + "..." if len(bridge.fingerprint) > 16 else bridge.fingerprint
        print(f"  [{index}] {bridge.kind:10s} {bridge.address:30s} {fp}")
    print(f"[parse] {len(valid)} valid of {len(lines)}")
    return valid


def main(argv: list[str]) -> int:
    lines = _read_bridges(argv)
    if not lines:
        print()
        print("[error] no bridge lines provided.")
        print("Usage:")
        print("  python tools/test_tor.py <bridges.txt>")
        print("  Get-Content bridges.txt | python tools/test_tor.py -")
        print("  python tools/test_tor.py     # interactive paste")
        return 2

    valid = _validate(lines)
    if not valid:
        print("[error] no valid bridges to try.")
        return 2

    log_lines: list[str] = []

    def logger(text: str) -> None:
        log_lines.append(text)
        # Only print Tor notices/errors and our own messages
        if text.startswith("TOR ") or not text.startswith("TOR Oct"):
            print(text)

    print()
    print(BANNER)
    print("[tor] starting Tor with these bridges (timeout: 120s)")
    print(BANNER)

    manager = TorManager(log=logger)
    started = time.monotonic()
    try:
        manager.start(bridges=valid, exit_country="")
    except TorError as exc:
        print()
        print(BANNER)
        print("[FAIL] Tor could not start")
        print(BANNER)
        print(str(exc))
        print()
        print("Last 30 Tor log lines:")
        for line in log_lines[-30:]:
            print("  " + line)
        return 1
    except Exception as exc:
        print(f"[FAIL] unexpected error: {type(exc).__name__}: {exc}")
        return 1

    elapsed = time.monotonic() - started
    print()
    print(BANNER)
    print(f"[OK] Tor bootstrapped in {elapsed:.1f}s")
    print(BANNER)
    print(f"  SOCKS   : {manager.socks_endpoint[0]}:{manager.socks_endpoint[1]}")
    print(f"  Control : {manager.control_endpoint[0]}:{manager.control_endpoint[1]}")
    print(f"  Bridges : {len(valid)}")

    # ---- Exit IP test ----
    print()
    print("[net] querying exit IP via check.torproject.org ...")
    try:
        exit_ip = manager.current_exit_ip(timeout=20.0)
    except Exception as exc:
        exit_ip = ""
        print(f"      exit-ip query failed: {type(exc).__name__}: {exc}")
    if exit_ip:
        print(f"      exit IP = {exit_ip}")
    else:
        print("      exit IP could not be determined (but Tor bootstrapped)")

    # ---- Simple HTTP fetch through the tunnel ----
    print()
    print("[net] fetching https://check.torproject.org/api/ip through Tor ...")
    try:
        import requests
    except ImportError:
        print("      (requests not available; skipping HTTP check)")
    else:
        proxies = {
            "http": f"socks5h://{manager.socks_endpoint[0]}:{manager.socks_endpoint[1]}",
            "https": f"socks5h://{manager.socks_endpoint[0]}:{manager.socks_endpoint[1]}",
        }
        session = requests.Session()
        session.trust_env = False
        try:
            response = session.get(
                "https://check.torproject.org/api/ip",
                proxies=proxies,
                timeout=20.0,
                headers={"User-Agent": "UAC-Spoofer-Desktop/test"},
            )
            data = response.json()
            print(f"      status   = {response.status_code}")
            print(f"      is_tor   = {data.get('IsTor')}")
            print(f"      exit_ip  = {data.get('IP')}")
        except Exception as exc:
            print(f"      HTTP check failed: {type(exc).__name__}: {exc}")
        finally:
            session.close()

    print()
    print("[shutdown] stopping Tor ...")
    manager.stop()
    print("[done]")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except KeyboardInterrupt:
        print("\n[interrupt] Ctrl+C received; exiting")
        raise SystemExit(130)