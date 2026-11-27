from __future__ import annotations

import ipaddress
import re
import time
from threading import RLock, Thread
from typing import Any

from ..connectors.terminal.securecrt import SecureCRTBridgeClient, SecureCRTBridgeError


_ID_BEGIN = "__ALLSRE_ID_B__"
_ID_IP = "__ALLSRE_ID_I__"
_ID_USER = "__ALLSRE_ID_U__"
_ID_END = "__ALLSRE_ID_E__"
IDENTITY_COMMAND = (
    f"printf '\\n{_ID_BEGIN}\\n'; hostname; "
    f"printf '\\n{_ID_IP}\\n'; "
    "ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1; "
    f"printf '\\n{_ID_USER}\\n'; whoami; printf '\\n{_ID_END}\\n'"
)
FAILED_IDENTITY_TTL_SECONDS = 60.0


def _clean_line(value: str) -> str:
    value = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", str(value or ""))
    return value.replace("\r", "").strip().strip("'\"")


def parse_identity(output: str) -> tuple[str, str]:
    lines = [_clean_line(line) for line in str(output or "").replace("\r", "").split("\n")]
    try:
        begin = max(i for i, line in enumerate(lines) if line == _ID_BEGIN)
        ip_marker = max(i for i, line in enumerate(lines) if line == _ID_IP)
    except ValueError:
        return "", ""
    host = next((line for line in lines[begin + 1:ip_marker] if line), "")
    ip = ""
    for line in lines[ip_marker + 1:]:
        if line in {_ID_USER, _ID_END}:
            break
        if line:
            ip = line
            break
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", host):
        return "", ""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return "", ""
    return host, ip


class PersonalTerminalDirectory:
    """Read-only SecureCRT inventory with marker-based identity checks."""

    def __init__(self, settings: Any, terminals: Any) -> None:
        self._settings = settings
        self._terminals = terminals
        self._cache: dict[str, dict[str, Any]] = {}
        self._lock = RLock()
        self._started = False

    def _securecrt_config(self) -> dict[str, Any]:
        return dict(self._settings.securecrt or {})

    def _client(self) -> SecureCRTBridgeClient:
        return SecureCRTBridgeClient.from_config(
            self._securecrt_config(), config_dir=self._settings.data_dir,
        )

    def start_background(self, interval: float = 10.0) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True

        def loop() -> None:
            while True:
                try:
                    self.list_terminals()
                except Exception:
                    pass
                time.sleep(max(1.0, interval))

        Thread(target=loop, daemon=True, name="personal-terminal-scan").start()

    def _identity(self, client: SecureCRTBridgeClient, terminal_id: str) -> dict[str, Any]:
        now = time.monotonic()
        cached = self._cache.get(terminal_id)
        if cached and (cached.get("ok") or now - float(cached.get("at") or 0) < FAILED_IDENTITY_TTL_SECONDS):
            return cached
        result: dict[str, Any] = {"ok": False, "at": now}
        for attempt in range(2):
            try:
                raw = client.execute(terminal_id, IDENTITY_COMMAND, 10)
                name, ip = parse_identity(str(raw.get("output") or ""))
                if name and ip:
                    result = {"ok": True, "name": name, "ip": ip, "at": now}
                    break
            except (SecureCRTBridgeError, OSError):
                pass
            if attempt == 0:
                time.sleep(0.5)
        with self._lock:
            self._cache[terminal_id] = result
        return result

    def list_terminals(self, project_session_id: str | None = None) -> list[dict[str, Any]]:
        del project_session_id
        if not self._securecrt_config().get("enabled", True):
            return []
        client = self._client()
        try:
            sessions = client.list_sessions()
            items: list[dict[str, Any]] = []
            seen_targets: set[tuple[str, str]] = set()
            alive: set[str] = set()
            for session in sessions:
                terminal_id = str(session.get("sessionId") or "")
                if not terminal_id or str(session.get("status") or "").upper() != "READY":
                    continue
                identity = self._identity(client, terminal_id)
                if not identity.get("ok"):
                    continue
                alive.add(terminal_id)
                target = (str(identity["name"]), str(identity["ip"]))
                if target in seen_targets:
                    continue
                seen_targets.add(target)
                items.append({
                    "terminalId": terminal_id,
                    "name": identity["name"],
                    "ip": identity["ip"],
                    "address": str(session.get("address") or ""),
                    "kind": "securecrt",
                })
            with self._lock:
                for stale in set(self._cache) - alive:
                    self._cache.pop(stale, None)
            return items
        finally:
            client.close()

    def execute_terminal(self, terminal_id: str | None, command: str, timeout: int,
                         terminal_mode: str = "AUTO",
                         raw_input: bool | None = None) -> dict[str, Any]:
        selected = str(terminal_id or "").strip()
        if not selected:
            available = self.list_terminals()
            if len(available) != 1:
                raise RuntimeError("terminal_required")
            selected = str(available[0]["terminalId"])
        result = self._terminals.execute(
            selected, command, timeout, terminal_mode=terminal_mode, raw_input=raw_input,
        )
        return {
            "output": result.get("output") or "",
            "exit_code": result.get("exit_code"),
            "status": result.get("status"),
            "error_code": result.get("error_code"),
            "error_message": result.get("error_message"),
        }

    def focus_terminal(self, terminal_id: str) -> dict[str, Any]:
        return self._terminals.focus(terminal_id)
