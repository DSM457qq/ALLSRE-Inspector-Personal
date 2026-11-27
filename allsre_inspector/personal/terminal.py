from __future__ import annotations

from pathlib import Path
from typing import Any

from ..connectors.terminal.securecrt import SecureCRTBridgeClient, SecureCRTBridgeError


class PersonalTerminalService:
    """SecureCRT-only terminal service for a standalone personal Inspector."""

    def __init__(self, settings: Any) -> None:
        self.config = dict(settings.securecrt or {})
        self.config_dir = Path(settings.data_dir)

    def _client(self) -> SecureCRTBridgeClient:
        return SecureCRTBridgeClient.from_config(self.config, config_dir=self.config_dir)

    def list(self) -> list[dict[str, Any]]:
        if not self.config.get("enabled", True):
            return []
        client = self._client()
        try:
            result = []
            for item in client.list_sessions():
                session_id = str(item.get("sessionId") or "")
                if not session_id:
                    continue
                result.append({
                    "terminalId": session_id,
                    "serverId": 0,
                    "projectSessionId": "",
                    "state": str(item.get("status") or "UNKNOWN").upper(),
                    "address": str(item.get("address") or ""),
                    "bridgeSessionId": session_id,
                })
            return result
        finally:
            client.close()

    def status(self, terminal_id: str) -> dict[str, Any]:
        for item in self.list():
            if str(item.get("terminalId")) == str(terminal_id):
                return {"state": item.get("state") or "UNKNOWN"}
        return {"state": "CLOSED"}

    def execute(self, terminal_id: str, command: str, timeout: int, *,
                terminal_mode: str = "AUTO",
                raw_input: bool | None = None) -> dict[str, Any]:
        client = self._client()
        try:
            return client.execute(
                terminal_id, command, timeout,
                terminal_mode=terminal_mode, raw_input=raw_input,
            )
        finally:
            client.close()

    def focus(self, terminal_id: str) -> dict[str, Any]:
        client = self._client()
        try:
            client.focus_terminal(terminal_id)
            return {"ok": True, "terminalId": terminal_id}
        finally:
            client.close()

    def health(self) -> dict[str, Any]:
        try:
            client = self._client()
            try:
                return {"available": True, "sessions": len(client.list_sessions())}
            finally:
                client.close()
        except (OSError, SecureCRTBridgeError) as exc:
            return {"available": False, "error": type(exc).__name__}
