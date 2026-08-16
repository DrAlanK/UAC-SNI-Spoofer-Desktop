from __future__ import annotations

import os
import sys
from pathlib import Path

import psutil


_DLL_HANDLES: list[object] = []


def _candidate_dlls() -> tuple[Path, ...]:
    windows = Path(os.getenv("WINDIR", r"C:\Windows"))

    values = [
        windows / "System32" / "Npcap" / "wpcap.dll",
        windows / "Sysnative" / "Npcap" / "wpcap.dll",
        windows / "System32" / "wpcap.dll",
        windows / "SysWOW64" / "Npcap" / "wpcap.dll",
        windows / "SysWOW64" / "wpcap.dll",
    ]

    seen: set[str] = set()
    result: list[Path] = []

    for value in values:
        key = str(value).casefold()
        if key in seen:
            continue

        seen.add(key)
        result.append(value)

    return tuple(result)


def activate_npcap_path() -> Path | None:
    for dll in _candidate_dlls():
        try:
            if not dll.is_file() or dll.stat().st_size <= 0:
                continue
        except OSError:
            continue

        directory = dll.parent

        if directory.name.casefold() == "npcap":
            current = os.environ.get("PATH", "")
            entries = [
                item
                for item in current.split(os.pathsep)
                if item
            ]

            if str(directory).casefold() not in {
                item.casefold()
                for item in entries
            }:
                os.environ["PATH"] = (
                    str(directory)
                    + os.pathsep
                    + current
                )

            add_directory = getattr(
                os,
                "add_dll_directory",
                None,
            )

            if callable(add_directory):
                try:
                    handle = add_directory(str(directory))
                    _DLL_HANDLES.append(handle)
                except OSError:
                    pass

        return dll

    return None


def _service_running(name: str) -> bool:
    if sys.platform != "win32":
        return False

    service_getter = getattr(
        psutil,
        "win_service_get",
        None,
    )

    if service_getter is None:
        return False

    try:
        service = service_getter(name)
        return service.status().casefold() == "running"
    except (psutil.Error, OSError):
        return False


def npcap_available() -> bool:
    if sys.platform != "win32":
        return True

    if activate_npcap_path() is None:
        return False

    return any(
        _service_running(service)
        for service in ("npcap", "npf")
    )


__all__ = [
    "activate_npcap_path",
    "npcap_available",
]