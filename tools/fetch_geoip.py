#!/usr/bin/env python3
"""Download Tor's GeoIP database files into bin/tor/.

The Tor Expert Bundle >= 13.5.x no longer ships geoip / geoip6, but
Tor still needs them to honour ``ExitNodes {XX}``. This script pulls
the latest copies from Tor's git repository.
"""

from __future__ import annotations

import shutil
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "bin" / "tor"

SOURCES = {
    "geoip": "https://gitlab.torproject.org/tpo/core/tor/-/raw/release-0.4.9/src/config/geoip",
    "geoip6": "https://gitlab.torproject.org/tpo/core/tor/-/raw/release-0.4.9/src/config/geoip6",
}
USER_AGENT = "UAC-Spoofer-Desktop/geoip-fetch"


def download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    tmp = dest.with_suffix(dest.suffix + ".part")
    print(f"[geoip] downloading {url}")
    with urllib.request.urlopen(req, timeout=120) as response, tmp.open("wb") as out:
        shutil.copyfileobj(response, out, 1024 * 256)
    tmp.replace(dest)
    print(f"[geoip] saved {dest.name} ({dest.stat().st_size / 1024:.0f} KB)")


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        target = DEST / name
        if target.is_file() and target.stat().st_size > 100_000:
            print(f"[geoip] {name} already present, skipping")
            continue
        try:
            download(url, target)
        except Exception as exc:
            print(f"[geoip] ERROR {name}: {exc}")
            return 1
    print("[geoip] done")
    for name in SOURCES:
        path = DEST / name
        if path.is_file():
            print(f"  {path.relative_to(ROOT)}  ({path.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())