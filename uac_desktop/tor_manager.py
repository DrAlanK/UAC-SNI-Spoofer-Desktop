"""Tor + WebTunnel integration for UAC Spoofer Desktop.

Bundles the Tor Expert Bundle (tor.exe) plus the WebTunnel pluggable
transport client and controls the process through the Tor ControlPort
using ``stem``.

Public API
----------
TorManager            - owns a Tor process, exposes SOCKS5 endpoint
TorBridge             - dataclass for one parsed bridge line
parse_bridge_line()   - parse "webtunnel host:port FP url=..." lines
default_webtunnel_bridges() - built-in bridges for Iran operators
TorError              - raised on start/control failures

The manager is Windows-first; the same code works on Linux/macOS if
the Tor Expert Bundle layout is preserved under ``bin/tor/``.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

try:
    from stem.control import Controller, Signal
    from stem import ProtocolError as _StemProtocolError
    from stem import SocketError as _StemSocketError
    _STEM_AVAILABLE = True
except ImportError:  # pragma: no cover - graceful degradation
    Controller = None  # type: ignore[assignment]
    Signal = None  # type: ignore[assignment]
    _StemProtocolError = _StemSocketError = Exception  # type: ignore[misc]
    _STEM_AVAILABLE = False


LogFn = Callable[[str], None]

# Tor ports - deliberately offset from Tor Browser defaults (9050/9051)
DEFAULT_SOCKS_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 9150
DEFAULT_CONTROL_PORT = 9151
DEFAULT_DNS_PORT = 9153

START_TIMEOUT_S = 60.0
BOOTSTRAP_RE = re.compile(r"Bootstrapped\s+(\d+)%")
COUNTRY_RE = re.compile(r"^[A-Za-z]{2}$")

# Known pluggable transport client executables shipped with Tor Browser.
TRANSPORT_BINARIES = {
    "webtunnel": "webtunnel-client.exe",
    "obfs4": "obfs4proxy.exe",
    "snowflake": "snowflake-client.exe",
    "meek_lite": "meek-client.exe",
}


class TorError(RuntimeError):
    """Raised when Tor fails to start, bootstrap or accept a control command."""


@dataclass(frozen=True)
class TorBridge:
    """One parsed Tor bridge line, ready to be written into torrc."""

    kind: str
    address: str
    fingerprint: str = ""
    url: str = ""
    extra: tuple[tuple[str, str], ...] = ()
    raw: str = ""

    def to_torrc(self) -> str:
        parts = [f"Bridge {self.kind} {self.address}"]
        if self.fingerprint:
            parts.append(self.fingerprint)
        if self.url:
            parts.append(f"url={self.url}")
        for key, value in self.extra:
            parts.append(f"{key}={value}")
        return " ".join(parts)

    @property
    def is_webtunnel(self) -> bool:
        return self.kind == "webtunnel"


def parse_bridge_line(line: str) -> TorBridge | None:
    """Parse a bridge line as distributed by Tor Project / BridgeDB.

    Supported::

        webtunnel 1.2.3.4:443 ABCD... url=https://example.com/xyz
        obfs4 1.2.3.4:443 ABCD... cert=... iat-mode=0
        snowflake 1.2.3.4:443 ABCD...
        meek_lite 1.2.3.4:443 url=https://... front=... utls=...

    Returns ``None`` for unsupported kinds or malformed lines.
    """
    if not line:
        return None
    tokens = str(line).strip().split()
    if len(tokens) < 2:
        return None
    kind = tokens[0].lower()
    if kind not in TRANSPORT_BINARIES and kind != "vanilla":
        return None
    address = tokens[1]
    if ":" not in address:
        return None
    fingerprint = ""
    url = ""
    extra: list[tuple[str, str]] = []
    for token in tokens[2:]:
        if "=" in token:
            key, value = token.split("=", 1)
            key = key.strip()
            if key.lower() == "url":
                url = value.strip()
            elif key.lower() in {"front", "utls", "cert", "iat-mode", "mode"}:
                extra.append((key, value.strip()))
        elif not fingerprint:
            fingerprint = token.strip()
    return TorBridge(
        kind=kind,
        address=address,
        fingerprint=fingerprint,
        url=url,
        extra=tuple(extra),
        raw=str(line).strip(),
    )


def default_webtunnel_bridges() -> list[TorBridge]:
    """Return the built-in WebTunnel bridges used as a fallback.

    These are the bridges published by Tor Project's BridgeDB for
    restricted environments. Replace them with your own bridge lines
    for maximum reliability inside Iran.
    """
    raw_lines = (
        # Placeholder lines - replace with fresh bridges from
        # https://bridges.torproject.org/ (webtunnel, IPv4/IPv6)
        "webtunnel [2001:db8:aaaa::1]:443 "
        "0123456789ABCDEF0123456789ABCDEF01234567 "
        "url=https://bridge.example.org/very-secret-path",
        "webtunnel 192.0.2.10:443 "
        "89ABCDEF0123456789ABCDEF0123456789ABCDEF "
        "url=https://cdn.example.net/tunnel-entry",
    )
    parsed = [parse_bridge_line(line) for line in raw_lines]
    return [bridge for bridge in parsed if bridge is not None]


class TorManager:
    """Own one Tor process and expose its SOCKS5 endpoint.

    Lifecycle::

        manager = TorManager(log=print)
        manager.start(bridges=[...], exit_country="us")
        # ... use manager.socks_endpoint ...
        manager.set_exit_country("de")
        manager.new_identity()
        manager.stop()
    """

    def __init__(
        self,
        log: LogFn | None = None,
        bundle_dir: Path | None = None,
        socks_port: int = DEFAULT_SOCKS_PORT,
        control_port: int = DEFAULT_CONTROL_PORT,
        dns_port: int = DEFAULT_DNS_PORT,
    ) -> None:
        self.log = log or (lambda _message: None)
        self.bundle_dir = Path(
            bundle_dir or (Path(__file__).resolve().parent.parent / "bin" / "tor")
        )
        self.socks_port = int(socks_port)
        self.control_port = int(control_port)
        self.dns_port = int(dns_port)
        self._process: subprocess.Popen | None = None
        self._controller: "Controller | None" = None
        self._torrc_path: Path | None = None
        self._data_dir: Path | None = None
        self._log_thread: threading.Thread | None = None
        self._bootstrap = 0
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._exit_country = ""
        self._bridges: list[TorBridge] = []
        self._pluggable_transports: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Read-only properties
    # ------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def bootstrapped(self) -> int:
        return self._bootstrap

    @property
    def exit_country(self) -> str:
        return self._exit_country

    @property
    def socks_endpoint(self) -> tuple[str, int]:
        return DEFAULT_SOCKS_HOST, self.socks_port

    @property
    def control_endpoint(self) -> tuple[str, int]:
        return DEFAULT_SOCKS_HOST, self.control_port

    # ------------------------------------------------------------------
    # Binary discovery
    # ------------------------------------------------------------------
    def _tor_binary(self) -> Path:
        name = "tor.exe" if sys.platform == "win32" else "tor"
        path = self.bundle_dir / name
        if not path.is_file():
            raise TorError(
                f"Tor binary not found: {path}. "
                "Run install-tor.ps1 once, or copy the Tor Expert Bundle "
                "into the project's bin/tor/ directory."
            )
        return path

    def _discover_pluggable_transports(self) -> dict[str, str]:
        found: dict[str, str] = {}
        for kind, filename in TRANSPORT_BINARIES.items():
            candidate = self.bundle_dir / "pluggable_transports" / filename
            if candidate.is_file():
                found[kind] = str(candidate)
        return found

    # ------------------------------------------------------------------
    # torrc generation
    # ------------------------------------------------------------------
    def _write_torrc(
        self,
        bridges: list[TorBridge],
        exit_country: str,
        data_dir: Path,
    ) -> Path:
        self._pluggable_transports = self._discover_pluggable_transports()
        lines: list[str] = [
            f"SocksPort {DEFAULT_SOCKS_HOST}:{self.socks_port}",
            f"ControlPort {DEFAULT_SOCKS_HOST}:{self.control_port}",
            "CookieAuthentication 1",
            f"DataDirectory {data_dir}",
            "Log notice file "
            + str(data_dir / "notices.log"),
            "Log notice stdout",
            "AvoidDiskWrites 1",
            "ClientOnly 1",
            "GeoIPFile " + str(self.bundle_dir / "geoip"),
            "GeoIPv6File " + str(self.bundle_dir / "geoip6"),
        ]
        # WebTunnel / obfs4 / snowflake client registration
        registered: set[str] = set()
        for bridge in bridges:
            if bridge.kind in self._pluggable_transports and bridge.kind not in registered:
                lines.append(
                    f"ClientTransportPlugin {bridge.kind} exec "
                    f"{self._pluggable_transports[bridge.kind]}"
                )
                registered.add(bridge.kind)
        if bridges:
            lines.append("UseBridges 1")
            for bridge in bridges:
                lines.append(bridge.to_torrc())
        if exit_country:
            code = exit_country.lower()
            if not COUNTRY_RE.fullmatch(code):
                raise TorError(f"Invalid exit country code: {exit_country!r}")
            lines.append(f"ExitNodes {{{code}}}")
            lines.append("StrictNodes 1")
        torrc = data_dir / "torrc"
        torrc.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return torrc

    # ------------------------------------------------------------------
    # Process control
    # ------------------------------------------------------------------
    def _drain_logs(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        for line in process.stdout:
            text = line.strip()
            if not text:
                continue
            match = BOOTSTRAP_RE.search(text)
            if match:
                self._bootstrap = int(match.group(1))
            self.log("TOR " + text)
            if self._stop_event.is_set():
                break

    def _wait_for_socks(self, timeout: float = START_TIMEOUT_S) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._stop_event.is_set():
                return False
            if self._process is not None and self._process.poll() is not None:
                return False
            try:
                with socket.create_connection(
                    (DEFAULT_SOCKS_HOST, self.socks_port), timeout=0.3
                ) as connection:
                    connection.settimeout(0.3)
                    connection.sendall(b"\x05\x01\x00")
                    if connection.recv(2) == b"\x05\x00":
                        return True
            except OSError:
                time.sleep(0.15)
        return False

    def _connect_controller(self) -> "Controller":
        if not _STEM_AVAILABLE:
            raise TorError(
                "stem is not installed. Run: pip install stem"
            )
        cookie_path = self._data_dir / "control_auth_cookie" if self._data_dir else None
        controller = Controller.from_port(
            address=DEFAULT_SOCKS_HOST, port=self.control_port
        )
        if cookie_path and cookie_path.is_file():
            try:
                controller.authenticate()
            except (_StemProtocolError, _StemSocketError, OSError):
                controller.authenticate()
        else:
            # Password-less or cookie auth; Tor writes the cookie when
            # CookieAuthentication is on.
            controller.authenticate()
        return controller

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start(
        self,
        bridges: list[TorBridge] | list[str] | None = None,
        exit_country: str = "",
    ) -> None:
        with self._lock:
            if self.running:
                return
            parsed: list[TorBridge] = []
            for item in bridges or default_webtunnel_bridges():
                bridge = item if isinstance(item, TorBridge) else parse_bridge_line(item)
                if bridge is not None:
                    parsed.append(bridge)
            if not parsed:
                raise TorError("Tor start requires at least one valid bridge line")
            self._bridges = parsed
            self._stop_event.clear()
            self._bootstrap = 0

            data_dir = Path(tempfile.mkdtemp(prefix="uac-tor-"))
            self._data_dir = data_dir
            torrc = self._write_torrc(parsed, exit_country, data_dir)
            self._torrc_path = torrc

            creation = (
                subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            binary = self._tor_binary()
            self.log(
                f"TOR starting bundle={binary} bridges={len(parsed)} "
                f"exit={exit_country or 'auto'}"
            )
            self._process = subprocess.Popen(
                [str(binary), "-f", str(torrc)],
                cwd=str(self.bundle_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=creation,
            )
            self._log_thread = threading.Thread(
                target=self._drain_logs, name="tor-log", daemon=True
            )
            self._log_thread.start()

            if not self._wait_for_socks():
                self.stop()
                raise TorError("Tor did not open its SOCKS port in time")
            try:
                self._controller = self._connect_controller()
            except Exception as exc:
                self.stop()
                raise TorError(f"Tor ControlPort authentication failed: {exc}") from exc

            if exit_country:
                self.set_exit_country(exit_country)
            self._exit_country = exit_country.lower()
            self.log(
                f"TOR ready socks={DEFAULT_SOCKS_HOST}:{self.socks_port} "
                f"exit={self._exit_country or 'auto'}"
            )

    def stop(self) -> None:
        with self._lock:
            self._stop_event.set()
            controller = self._controller
            self._controller = None
            if controller is not None:
                try:
                    controller.close()
                except Exception:
                    pass
            process = self._process
            self._process = None
            if process is not None and process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
            thread = self._log_thread
            self._log_thread = None
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=1.0)
            if self._data_dir is not None:
                try:
                    import shutil
                    shutil.rmtree(self._data_dir, ignore_errors=True)
                except Exception:
                    pass
                self._data_dir = None
            self._torrc_path = None
            self._bootstrap = 0

    # ------------------------------------------------------------------
    # ControlPort helpers
    # ------------------------------------------------------------------
    def _require_controller(self) -> "Controller":
        if self._controller is None:
            raise TorError("Tor ControlPort is not connected")
        return self._controller

    def set_exit_country(self, country_code: str) -> None:
        """Pin the exit relay to one ISO 3166-1 alpha-2 country.

        Pass an empty string to allow any exit.
        """
        controller = self._require_controller()
        code = (country_code or "").strip().lower()
        if code and not COUNTRY_RE.fullmatch(code):
            raise TorError(f"Invalid exit country: {country_code!r}")
        try:
            if code:
                controller.set_conf("ExitNodes", f"{{{code}}}")
                controller.set_conf("StrictNodes", "1")
                self.log(f"TOR exit pinned to {code.upper()}")
            else:
                controller.reset_conf("ExitNodes")
                controller.reset_conf("StrictNodes")
                self.log("TOR exit unpinned (any country)")
            self._exit_country = code
        except (_StemProtocolError, _StemSocketError, OSError) as exc:
            raise TorError(f"Could not update ExitNodes: {exc}") from exc

    def get_exit_country(self) -> str:
        return self._exit_country

    def new_identity(self) -> None:
        """Ask Tor for a fresh circuit (new exit IP) without restarting."""
        controller = self._require_controller()
        try:
            controller.signal(Signal.NEWNYM)
        except (_StemProtocolError, _StemSocketError, OSError) as exc:
            raise TorError(f"NEWNYM failed: {exc}") from exc
        self.log("TOR NEWNYM requested")

    def current_exit_ip(self) -> str:
        """Query the exit relay's IP through the SOCKS proxy.

        Uses Tor's own ``check.torproject.org`` endpoint so the answer
        reflects what websites actually see.
        """
        try:
            import requests
        except ImportError:
            return ""
        proxies = {
            "http": f"socks5h://{DEFAULT_SOCKS_HOST}:{self.socks_port}",
            "https": f"socks5h://{DEFAULT_SOCKS_HOST}:{self.socks_port}",
        }
        try:
            session = requests.Session()
            session.trust_env = False
            response = session.get(
                "https://check.torproject.org/api/ip",
                proxies=proxies,
                timeout=8,
                headers={"User-Agent": "UAC-Spoofer-Desktop/Tor"},
            )
            value = response.json()
            if value.get("IsTor"):
                return str(value.get("IP", ""))
        except Exception as exc:
            self.log(f"TOR exit ip check failed: {type(exc).__name__}")
            return ""
        return ""


__all__ = [
    "DEFAULT_CONTROL_PORT",
    "DEFAULT_SOCKS_HOST",
    "DEFAULT_SOCKS_PORT",
    "TorBridge",
    "TorError",
    "TorManager",
    "default_webtunnel_bridges",
    "parse_bridge_line",
]