#!/usr/bin/env python3
"""
fetch_tor_bundle.py - Download Tor runtime files for packaging.

Fetches the Tor Expert Bundle (Windows x86_64, contains tor.exe +
geoip data) and the WebTunnel pluggable-transport client, placing
them under bin/tor/ so the PyInstaller build can bundle them.

Runs on Linux, macOS and Windows with Python 3.8+.

Usage:
    python tools/fetch_tor_bundle.py
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "bin" / "tor"
TRANSPORTS = DEST / "pluggable_transports"

DIST_INDEX = "https://dist.torproject.org/torbrowser/"
EXPERT_URL = DIST_INDEX + "{v}/tor-expert-bundle-windows-x86_64-{v}.tar.gz"
BROWSER_URL = DIST_INDEX + "{v}/tor-browser-windows-x86_64-portable-{v}.exe"
FALLBACK_VERSION = "13.5.7"
USER_AGENT = "UAC-Spoofer-Desktop/tor-fetch"


def log(msg: str) -> None:
    print(f"[fetch-tor] {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"[fetch-tor] WARN {msg}", flush=True)


def download(url: str, dest: Path) -> None:
    log(f"downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        with urllib.request.urlopen(req, timeout=180) as response, tmp.open("wb") as out:
            shutil.copyfileobj(response, out, 1024 * 256)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} for {url}") from exc
    tmp.replace(dest)
    log(f"saved {dest.name} ({dest.stat().st_size / (1024 * 1024):.1f} MB)")


def latest_version() -> str:
    log("querying dist.torproject.org ...")
    try:
        req = urllib.request.Request(DIST_INDEX, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as r:
            html = r.read().decode("utf-8", "replace")
    except Exception as exc:
        warn(f"could not query index: {exc}; using fallback {FALLBACK_VERSION}")
        return FALLBACK_VERSION
    versions = re.findall(r'href="(\d+\.\d+\.\d+)/"', html)
    if not versions:
        return FALLBACK_VERSION
    versions.sort(key=lambda v: tuple(int(x) for x in v.split(".")), reverse=True)
    return versions[0]


def clean_dest() -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    TRANSPORTS.mkdir(parents=True, exist_ok=True)
    for item in DEST.iterdir():
        if item.name == "pluggable_transports":
            continue
        if item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
        else:
            item.unlink(missing_ok=True)


def extract_targz(archive: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        try:
            tar.extractall(path=out_dir, filter="data")
        except TypeError:
            # Python < 3.12 has no filter argument
            tar.extractall(path=out_dir)


def fetch_expert_bundle(version: str) -> None:
    url = EXPERT_URL.format(v=version)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        archive = tmpdir / f"tor-expert-{version}.tar.gz"
        download(url, archive)
        log("extracting expert bundle ...")
        extracted = tmpdir / "expert"
        extract_targz(archive, extracted)
        candidates = list(extracted.rglob("tor.exe"))
        if not candidates:
            raise RuntimeError("tor.exe not found in expert bundle")
        src_root = candidates[0].parent
        log(f"installing from {src_root.relative_to(extracted)}/")
        for item in src_root.iterdir():
            target = DEST / item.name
            if item.is_dir():
                shutil.copytree(item, target, dirs_exist_ok=True)
            else:
                shutil.copy2(item, target)
    log("expert bundle installed")


def extract_7z(archive: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    seven = next(
        (shutil.which(name) for name in ("7z", "7za", "7zr")
         if shutil.which(name)),
        None,
    )
    if seven:
        log(f"extracting with {seven} ...")
        result = subprocess.run(
            [seven, "x", "-y", f"-o{out_dir}", str(archive)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"7z failed: {(result.stderr or result.stdout).strip()}"
            )
        return
    try:
        import py7zr
    except ImportError:
        log("py7zr missing; installing ...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", "py7zr"]
        )
        import py7zr
    log("extracting with py7zr (this may take a while) ...")
    with py7zr.SevenZipFile(archive, "r") as zf:
        zf.extractall(path=out_dir)


def fetch_webtunnel(version: str) -> None:
    target = TRANSPORTS / "webtunnel-client.exe"
    if target.is_file():
        log("webtunnel-client.exe already present; skipping Tor Browser download")
        return
    url = BROWSER_URL.format(v=version)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        archive = tmpdir / f"tor-browser-{version}.exe"
        download(url, archive)
        log("extracting Tor Browser archive (may take 1-2 minutes) ...")
        extracted = tmpdir / "tb"
        extract_7z(archive, extracted)
        candidates = list(extracted.rglob("webtunnel-client.exe"))
        if not candidates:
            raise RuntimeError("webtunnel-client.exe not found in Tor Browser")
        shutil.copy2(candidates[0], target)
    log(f"installed webtunnel-client.exe ({target.stat().st_size / 1024:.0f} KB)")


def ensure_python_deps() -> None:
    missing = []
    try:
        import stem  # noqa: F401
    except ImportError:
        missing.append("stem>=1.8.2")
    try:
        import socks  # noqa: F401
    except ImportError:
        missing.append("requests[socks]>=2.31")
    if missing:
        log(f"installing Python deps: {', '.join(missing)}")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", *missing]
        )


def main() -> int:
    print()
    log(f"project root: {ROOT}")
    version = latest_version()
    log(f"target Tor version: {version}")
    clean_dest()
    try:
        fetch_expert_bundle(version)
    except Exception as exc:
        log(f"ERROR expert bundle: {exc}")
        return 1
    try:
        fetch_webtunnel(version)
    except Exception as exc:
        warn(f"webtunnel unavailable: {exc}")
        warn("Tor mode will start but bridges may fail to connect.")
    ensure_python_deps()
    print()
    log("done. final layout under bin/tor/:")
    for path in sorted(DEST.rglob("*")):
        if path.is_file():
            rel = path.relative_to(ROOT)
            size = path.stat().st_size
            log(f"  {rel}  ({size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())