"""Tor + WebTunnel integration for UAC Spoofer Desktop.

Bundles the Tor Expert Bundle (tor.exe) plus the WebTunnel pluggable
transport client and controls the process through the Tor ControlPort
using ``stem``.

Public API
----------
TorManager            - owns a Tor process, exposes SOCKS5 endpoint
TorBridge             - dataclass for one parsed bridge line
parse_bridge_line()   - parse "webtunnel host:port FP url=..." lines
default_webtunnel_bridges() - built-in bridges (empty, see docstring)
TorError              - raised on start/control failures
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

# Timeouts
SOCKS_TIMEOUT_S = 20.0            # how long to wait for SOCKS listener
BOOTSTRAP_TIMEOUT_S = 120.0       # how long to wait for full bootstrap
EXIT_IP_TIMEOUT_S = 15.0          # how long to wait for exit IP lookup

BOOTSTRAP_RE = re.compile(r"Bootstrapped\s+(\d+)%")
COUNTRY_RE = re.compile(r"^[A-Za-z]{2}$")

# Known pluggable transport client executables.
# Modern Tor (0.4.8+) ships a single lyrebird.exe that handles webtunnel,
# obfs4, snowflake and meek_lite in one process.
TRANSPORT_BINARIES = {
    "webtunnel": "lyrebird.exe",
    "obfs4": "lyrebird.exe",
    "snowflake": "lyrebird.exe",
    "meek_lite": "lyrebird.exe",
}

# Legacy per-transport clients shipped with older Tor bundles.
LEGACY_TRANSPORT_BINARIES = {
    "webtunnel": "webtunnel-client.exe",
    "obfs4": "obfs4proxy.exe",
    "snowflake": "snowflake-client.exe",
    "meek_lite": "meek-client.exe",
}

def fetch_webtunnel_bridges(
    country: str = "",
    timeout: float = 30.0,
) -> list[str]:
    """Fetch fresh WebTunnel bridges from the Tor Project moat API.

    Returns a list of validated bridge line strings.
    Raises TorError on network or parsing failures.
    """
    import requests

    url = "https://bridges.torproject.org/moat/circumvention/settings"
    payload = {
        "country": (country or "ir").lower()[:2],
        "transport": "webtunnel",
    }
    headers = {
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json",
        "User-Agent": "UAC-Spoofer-Desktop/Tor",
    }
    try:
        response = requests.post(
            url, json=payload, headers=headers, timeout=timeout
        )
    except requests.RequestException as exc:
        raise TorError(f"BridgeDB unreachable: {exc}") from exc

    if response.status_code != 200:
        raise TorError(f"BridgeDB returned HTTP {response.status_code}")

    try:
        data = response.json()
    except (ValueError, TypeError) as exc:
        raise TorError(f"BridgeDB returned malformed JSON: {exc}") from exc

    bridges: list[str] = []
    for setting in (data.get("settings") or []):
        if not isinstance(setting, dict):
            continue
        bridge_set = setting.get("bridges")
        if not isinstance(bridge_set, dict):
            continue
        kind = str(bridge_set.get("type") or "").lower()
        if kind != "webtunnel":
            continue
        for raw in (bridge_set.get("bridge_strings") or []):
            line = str(raw).strip()
            if line and parse_bridge_line(line) is not None:
                bridges.append(line)

    if not bridges:
        raise TorError(
            "BridgeDB returned no WebTunnel bridges. "
            "Try again later, or use the email / Telegram methods."
        )
    return bridges

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
    """Return built-in WebTunnel bridges.

    IMPORTANT: WebTunnel bridges are short-lived and country-specific.
    There is NO useful set of defaults we could ship - any cached list
    would be stale within days. The user must fetch fresh bridges from
    https://bridges.torproject.org/ (choose "WebTunnel" transport) and
    paste them into Tor Settings inside the app.

    This function exists so callers can safely fall back to an empty
    list rather than crash, and so the error path can point the user
    at the correct URL.
    """
    return []


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
        self._last_bootstrap_line = ""

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
        """Return a mapping of transport-kind -> client executable path.

        Prefers the modern single-binary ``lyrebird.exe`` (Tor >= 0.4.8)
        and falls back to legacy per-transport clients.
        """
        found: dict[str, str] = {}
        transports_dir = self.bundle_dir / "pluggable_transports"

        # Modern unified binary
        unified = transports_dir / "lyrebird.exe"
        if unified.is_file():
            for kind in TRANSPORT_BINARIES:
                found[kind] = str(unified)
            self.log("TOR transports: lyrebird.exe (webtunnel/obfs4/snowflake/meek_lite)")
            return found

        # Legacy per-transport binaries
        for kind, filename in LEGACY_TRANSPORT_BINARIES.items():
            candidate = transports_dir / filename
            if candidate.is_file():
                found[kind] = str(candidate)
        if found:
            self.log("TOR transports: legacy clients " + ", ".join(sorted(found)))
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
            "Log notice file " + str(data_dir / "notices.log"),
            "Log notice stdout",
            "AvoidDiskWrites 1",
            "ClientOnly 1",
        ]
        # Modern Tor embeds GeoIP data inside tor.exe, but older bundles
        # ship it as separate files. Only reference them if present.
        geoip = self.bundle_dir / "geoip"
        geoip6 = self.bundle_dir / "geoip6"
        if geoip.is_file():
            lines.append("GeoIPFile " + str(geoip))
        if geoip6.is_file():
            lines.append("GeoIPv6File " + str(geoip6))

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
                self._last_bootstrap_line = text
            self.log("TOR " + text)
            if self._stop_event.is_set():
                break

    def _wait_for_socks(self, timeout: float = SOCKS_TIMEOUT_S) -> bool:
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

    def _wait_for_bootstrap(self, timeout: float = BOOTSTRAP_TIMEOUT_S) -> bool:
        """Wait until Tor reports 'Bootstrapped 100%' or times out.

        Modern Tor first opens SOCKS/Control listeners and THEN bootstraps
        through the bridge. We must wait for full bootstrap before trying
        to route any traffic - otherwise exit IP lookups fail with
        ConnectTimeout.
        """
        deadline = time.monotonic() + timeout
        last_reported = -1
        while time.monotonic() < deadline:
            if self._stop_event.is_set():
                return False
            if self._process is not None and self._process.poll() is not None:
                return False
            current = self._bootstrap
            if current >= 100:
                return True
            if current != last_reported:
                self.log(f"TOR bootstrap {current}%")
                last_reported = current
            time.sleep(0.25)
        return False

    def _kill_stale_tor(self) -> int:
        """Terminate leftover tor.exe holding our SOCKS/Control ports.

        A crash or Ctrl+C in tools/test_tor.py can leave Tor running.
        Without this check, every subsequent start() fails with
        'Address already in use'.
        """
        if sys.platform != "win32":
            return 0
        try:
            import psutil
        except ImportError:
            return 0

        current_pid = os.getpid()
        try:
            target_binary = self._tor_binary().resolve()
        except Exception:
            target_binary = None

        killed = 0
        for process in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = process.info
                if int(info.get("pid", -1)) == current_pid:
                    continue
                if str(info.get("name") or "").lower() != "tor.exe":
                    continue
                exe_path = info.get("exe")
                if target_binary is not None and exe_path:
                    try:
                        if Path(exe_path).resolve() != target_binary:
                            continue
                    except (OSError, ValueError):
                        pass
                self.log(f"TOR killing stale tor.exe pid={info.get('pid')}")
                self._force_kill_process(process)
                killed += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
                continue
        if killed:
            self.log(f"TOR cleaned up {killed} stale process(es)")
            time.sleep(0.5)
        return killed

    @staticmethod
    def _force_kill_process(process) -> None:
        """Terminate, then forcibly kill if needed."""
        try:
            process.terminate()
            try:
                process.wait(timeout=2)
                return
            except Exception:
                pass
        except Exception:
            pass
        # Fallback to taskkill on Windows for stubborn processes
        if sys.platform == "win32":
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                    capture_output=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                return
            except Exception:
                pass
        try:
            process.kill()
        except Exception:
            pass
    
    def _connect_controller(self) -> "Controller":
        if not _STEM_AVAILABLE:
            raise TorError("stem is not installed. Run: pip install stem")
        controller = Controller.from_port(
            address=DEFAULT_SOCKS_HOST, port=self.control_port
        )
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
            raw_bridges = list(bridges) if bridges else default_webtunnel_bridges()
            for item in raw_bridges:
                bridge = item if isinstance(item, TorBridge) else parse_bridge_line(item)
                if bridge is not None:
                    parsed.append(bridge)
            if not parsed:
                raise TorError(
                    "No valid Tor bridges configured.\n\n"
                    "Get fresh WebTunnel bridges from:\n"
                    "  https://bridges.torproject.org/\n\n"
                    "Choose the 'WebTunnel' transport, copy the lines, "
                    "then open Tor Settings in the app and paste them "
                    "(one bridge per line)."
                )

            self._bridges = parsed
            self._stop_event.clear()
            self._bootstrap = 0
            self._last_bootstrap_line = ""

            self._kill_stale_tor()
            data_dir = Path(tempfile.mkdtemp(prefix="uac-tor-"))
            self._data_dir = data_dir
            torrc = self._write_torrc(parsed, exit_country, data_dir)
            self._torrc_path = torrc

            creation = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
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

            # ---- Step 1: wait for SOCKS listener ----
            if not self._wait_for_socks():
                self.stop()
                raise TorError("Tor did not open its SOCKS port in time")

            # ---- Step 2: connect to ControlPort ----
            try:
                self._controller = self._connect_controller()
            except Exception as exc:
                self.stop()
                raise TorError(f"Tor ControlPort authentication failed: {exc}") from exc

            # ---- Step 3: wait for full bootstrap ----
            self.log("TOR waiting for bootstrap...")
            if not self._wait_for_bootstrap():
                # Kill it and report the last known state
                last = self._last_bootstrap_line or f"{self._bootstrap}%"
                self.stop()
                raise TorError(
                    "Tor failed to bootstrap through the bridge.\n\n"
                    f"Last status: {last}\n\n"
                    "The bridge may be stale or unreachable. Get a fresh "
                    "WebTunnel bridge from https://bridges.torproject.org/"
                )

            # ---- Step 4: apply exit country if requested ----
            if exit_country:
                try:
                    self.set_exit_country(exit_country)
                except Exception as exc:
                    self.log(f"TOR exit country could not be set: {exc}")

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
                    import psutil
                    wrapper = psutil.Process(process.pid)
                    TorManager._force_kill_process(wrapper)
                except Exception:
                    try:
                        process.terminate()
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        try:
                            process.kill()
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

    def current_exit_ip(self, timeout: float = EXIT_IP_TIMEOUT_S) -> str:
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
                timeout=timeout,
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
    "fetch_webtunnel_bridges",
]