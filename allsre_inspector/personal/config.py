from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import os

import yaml


DEFAULT_FILE_STORAGE_NAME = "ALLSRE-files"


def _desktop_dir() -> Path:
    """Return the Windows desktop directory, including redirected desktops."""
    if os.name == "nt":
        try:
            import ctypes

            buffer = ctypes.create_unicode_buffer(32768)
            # CSIDL_DESKTOPDIRECTORY, not CSIDL_DESKTOP: the physical folder.
            if ctypes.windll.shell32.SHGetFolderPathW(
                None, 0x0010, None, 0, buffer
            ) == 0 and buffer.value:
                return Path(buffer.value)
        except Exception:
            pass
    return Path.home() / "Desktop"


def default_file_storage_dir() -> Path:
    return _desktop_dir() / DEFAULT_FILE_STORAGE_NAME


@dataclass(frozen=True)
class PersonalSettings:
    raw: dict[str, Any]
    source: Path

    @property
    def host(self) -> str:
        return str(self.raw.get("listen_host") or "127.0.0.1")

    @property
    def port(self) -> int:
        return int(self.raw.get("listen_port") or 8876)

    @property
    def data_dir(self) -> Path:
        value = Path(str(self.raw.get("data_dir") or "data"))
        return value if value.is_absolute() else (self.source.parent / value).resolve()

    @property
    def file_storage_dir(self) -> Path:
        configured = str(self.raw.get("file_storage_dir") or "").strip()
        if not configured:
            return default_file_storage_dir()
        value = Path(configured).expanduser()
        return value if value.is_absolute() else (self.source.parent / value).resolve()

    @property
    def securecrt(self) -> dict[str, Any]:
        return dict(self.raw.get("securecrt_bridge") or {})

    @property
    def opencode(self) -> dict[str, Any]:
        return dict(self.raw.get("opencode") or {})

    @property
    def bash_classification_enabled(self) -> bool:
        tools = dict((self.raw.get("agent_ui") or {}).get("tools") or {})
        value = tools.get("bash_classification_enabled", True)
        if isinstance(value, str):
            return value.strip().lower() not in {"0", "false", "no", "off"}
        return bool(value)


def load_settings(path: str | Path | None = None) -> PersonalSettings:
    source = Path(path or os.getenv("ALLSRE_INSPECTOR_CONFIG", "inspector.yaml")).resolve()
    if not source.is_file():
        raise RuntimeError(f"configuration file not found: {source}")
    raw = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    host = str(raw.get("listen_host") or "127.0.0.1")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("personal_inspector_must_bind_loopback")
    settings = PersonalSettings(raw, source)
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.file_storage_dir.mkdir(parents=True, exist_ok=True)
    securecrt = dict(raw.get("securecrt_bridge") or {})
    if securecrt.get("enabled", True):
        securecrt["enabled"] = True
        securecrt.setdefault("host", "127.0.0.1")
        securecrt.setdefault("port", 8765)
        securecrt["token_file"] = str(settings.data_dir / "securecrt-bridge" / "bridge.token")
        raw["securecrt_bridge"] = securecrt
    return settings
