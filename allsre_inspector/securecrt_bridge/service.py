from __future__ import annotations

from importlib import resources
import os
import re
import shutil
from pathlib import Path
from threading import Event, Thread
from typing import Any

from . import bridge_v2


_KEYMAP_FILENAME = re.compile(r'^S:"Keymap Filename V2"=(?P<value>.*?)(?:\r?\n)?$')
_KEYMAP_NAME = re.compile(r'^S:"Keymap Name"=(?P<value>.*?)(?:\r?\n)?$')
_SCRIPT_FILENAME = re.compile(r'^S:"Script Filename"=(?P<value>.*?)(?:\r?\n)?$')


class SecureCRTBridgeService:
    """Own one local SecureCRT Bridge inside the Inspector process."""

    def __init__(self, config: dict[str, Any], data_dir: Path) -> None:
        self.config = dict(config)
        self.enabled = bool(self.config.get("enabled", False))
        self.host = str(self.config.get("host") or "127.0.0.1")
        self.port = int(self.config.get("port") or 8765)
        self.runtime_dir = (Path(data_dir) / "securecrt-bridge").resolve()
        self.token_file = self.runtime_dir / "bridge.token"
        self.client_dir = self.runtime_dir / "client"
        self._stop = Event()
        self._ready = Event()
        self._thread: Thread | None = None
        self._error = ""
        self._repaired_sessions = 0

    def _session_dirs(self) -> list[Path]:
        """Return explicit and conventional SecureCRT session roots.

        Only configured roots and the conventional per-user location are
        scanned. On Windows, older ALLSRE deployments also used a versioned
        ``C:\\SecureCRT.*\\SecureCRT\\Config\\Sessions`` location, so include
        that narrow pattern without traversing arbitrary user directories.
        """
        values = [
            self.config.get("sessions_dir"),
            self.config.get("session_config_dir"),
            os.environ.get("SECURECRT_SESSIONS_DIR"),
        ]
        config_dir = str(os.environ.get("SECURECRT_CONFIG_DIR") or "").strip()
        if config_dir:
            values.append(str(Path(config_dir) / "Sessions"))
        appdata = str(os.environ.get("APPDATA") or "").strip()
        if appdata:
            values.append(str(Path(appdata) / "VanDyke" / "Config" / "Sessions"))
        if os.name == "nt":
            values.extend(str(path) for path in Path("C:/").glob(
                "SecureCRT.*/SecureCRT/Config/Sessions"
            ))
        roots: list[Path] = []
        seen: set[Path] = set()
        for value in values:
            if not value:
                continue
            root = Path(str(value)).expanduser()
            try:
                root = root.resolve()
            except OSError:
                continue
            if root.is_dir() and root not in seen:
                roots.append(root)
                seen.add(root)
        return roots

    @staticmethod
    def _keymap_path(value: str) -> Path:
        return Path(value.strip().strip('"')).expanduser()

    def _repair_stale_keymap_file(self, path: Path) -> bool:
        """Remove a missing ALLSRE lock-map override from one session INI."""
        try:
            original = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        lines = original.splitlines(keepends=True)
        keymap_name = ""
        keymap_filename = ""
        script_filename = ""
        for line in lines:
            name_match = _KEYMAP_NAME.match(line)
            if name_match is not None:
                keymap_name = str(name_match.group("value") or "").strip().lower()
            match = _KEYMAP_FILENAME.match(line)
            if match is not None:
                keymap_filename = str(match.group("value") or "")
            script_match = _SCRIPT_FILENAME.match(line)
            if script_match is not None:
                script_filename = str(script_match.group("value") or "")
        owns_script = script_filename.strip().lower().endswith("securecrt_bridge_v2.py")
        missing_lock_file = (
            keymap_filename.lower().endswith("agent-input-lock.key")
            and not self._keymap_path(keymap_filename).is_file()
        )
        # Previous versions could persist Custom with an empty filename before
        # the script was able to set AGENT_KEYMAP. Restrict this repair to
        # sessions that explicitly auto-run our bridge; do not touch a user's
        # unrelated custom keymap.
        incomplete_bridge_keymap = owns_script and keymap_name == "custom" and not keymap_filename.strip()
        stale = missing_lock_file or incomplete_bridge_keymap
        if not stale:
            return False
        rewritten: list[str] = []
        for line in lines:
            if _KEYMAP_FILENAME.match(line):
                continue
            match = _KEYMAP_NAME.match(line)
            if match is not None and str(match.group("value") or "").strip().lower() == "custom":
                ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
                rewritten.append('S:"Keymap Name"=Default' + ending)
                continue
            rewritten.append(line)
        updated = "".join(rewritten)
        backup = path.with_name(path.name + ".allsre-keymap-backup")
        temporary = path.with_name(path.name + ".allsre-keymap-tmp")
        try:
            if not backup.exists():
                backup.write_text(original, encoding="utf-8", newline="")
            temporary.write_text(updated, encoding="utf-8", newline="")
            temporary.replace(path)
        except OSError:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            return False
        return True

    def _repair_stale_keymaps(self) -> int:
        repaired = 0
        for root in self._session_dirs():
            for path in root.rglob("*.ini"):
                repaired += int(self._repair_stale_keymap_file(path))
        return repaired

    def _install_client_resources(self) -> None:
        self.client_dir.mkdir(parents=True, exist_ok=True)
        package = resources.files(__package__)
        for name in ("securecrt_bridge_v2.py", "agent-input-lock.key"):
            source = package.joinpath(name)
            target = self.client_dir / name
            with resources.as_file(source) as source_path:
                if not target.exists() or target.read_bytes() != source_path.read_bytes():
                    shutil.copyfile(source_path, target)

    def start(self, timeout: float = 5.0) -> None:
        if not self.enabled or self._thread is not None:
            return
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self._install_client_resources()
        self._repaired_sessions = self._repair_stale_keymaps()
        self._stop.clear()
        self._ready.clear()
        self._error = ""
        self._thread = Thread(target=self._run, name="securecrt-bridge", daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout):
            self.stop()
            detail = self._error or "SECURECRT_BRIDGE_START_TIMEOUT"
            raise RuntimeError(detail)
        if self._error:
            self.stop()
            raise RuntimeError(self._error)

    def _run(self) -> None:
        try:
            bridge_v2.IPC = self.runtime_dir / "ipc-v2"
            bridge_v2.TOKEN_FILE = self.token_file
            try:
                shell_keepalive_interval = float(
                    self.config.get("shell_keepalive_interval_seconds") or 90
                )
            except (TypeError, ValueError):
                shell_keepalive_interval = 90.0
            bridge_v2.REGISTRY = bridge_v2.Registry(
                shell_keepalive_enabled=bool(self.config.get("shell_keepalive_enabled", False)),
                shell_keepalive_interval_seconds=shell_keepalive_interval,
            )
            bridge_v2.main(host=self.host, port=self.port, stop_event=self._stop, ready_event=self._ready)
        except Exception as exc:
            self._error = f"SECURECRT_BRIDGE_START_FAILED:{type(exc).__name__}:{exc}"
            self._ready.set()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout)

    def diagnostics(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "host": self.host,
            "port": self.port,
            "available": bool(self.enabled and self._thread is not None and self._ready.is_set() and not self._error),
            "runtimeDir": str(self.runtime_dir),
            "clientScript": str(self.client_dir / "securecrt_bridge_v2.py"),
            "ipcDir": str(self.runtime_dir / "ipc-v2"),
            "tokenReady": self.token_file.is_file(),
            "repairedStaleKeymapSessions": self._repaired_sessions,
            "error": self._error or None,
        }
