from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any
import json
import socket
import time
import uuid

from .base64_transfer import Base64ShellTransfer


class SecureCRTBridgeError(RuntimeError):
    """A stable, non-secret error returned by the local SecureCRT bridge."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"{code}:{message}" if message else code)
        self.code = code


class SecureCRTBridgeClient:
    """Authenticated JSON-lines client for Inspector-managed SecureCRT Bridge."""

    def __init__(self, host: str, port: int, token: str, *, connect_timeout: float = 5) -> None:
        if not token or len(token) < 32:
            raise SecureCRTBridgeError("SECURECRT_BRIDGE_TOKEN_INVALID")
        self.sock = socket.create_connection((host, port), timeout=connect_timeout)
        self.buffer = b""
        self._lock = Lock()
        # Client-side launch baselines: the bridge no longer keeps reservations,
        # so "which window belongs to this launch" is resolved by diffing the
        # session list captured before the click.
        self._baselines: dict[str, set[str]] = {}
        try:
            response = self._exchange(
                {"type": "authenticate", "token": token}, connect_timeout,
            )
            if response.get("type") != "authenticated":
                raise SecureCRTBridgeError("SECURECRT_BRIDGE_AUTH_FAILED")
            # Older bridges bind a session at reserve time and can steal a
            # concurrently opened window; refuse that protocol before launch.
            if int(response.get("protocolVersion") or 0) < 2:
                raise SecureCRTBridgeError(
                    "SECURECRT_BRIDGE_UPGRADE_REQUIRED",
                    "restart the Inspector service",
                )
        except Exception:
            self.sock.close()
            raise

    @classmethod
    def from_config(
        cls, config: dict[str, Any], *, config_dir: Path | None = None,
    ) -> "SecureCRTBridgeClient":
        token = str(config.get("token") or "").strip()
        if not token:
            configured = Path(str(config.get("token_file") or "./data/securecrt-bridge/bridge.token"))
            if not configured.is_absolute():
                configured = (config_dir or Path.cwd()) / configured
            try:
                token = configured.resolve().read_text(encoding="ascii").strip()
            except OSError as exc:
                raise SecureCRTBridgeError("SECURECRT_BRIDGE_TOKEN_UNAVAILABLE") from exc
        return cls(
            str(config.get("host") or "127.0.0.1"),
            int(config.get("port") or 8765),
            token,
        )

    def _receive(self, timeout: float) -> dict[str, Any]:
        self.sock.settimeout(timeout)
        while b"\n" not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise SecureCRTBridgeError("SECURECRT_BRIDGE_DISCONNECTED")
            self.buffer += chunk
            if len(self.buffer) > 1024 * 1024:
                raise SecureCRTBridgeError("SECURECRT_BRIDGE_MESSAGE_TOO_LARGE")
        line, self.buffer = self.buffer.split(b"\n", 1)
        message = json.loads(line.decode("utf-8"))
        if not isinstance(message, dict):
            raise SecureCRTBridgeError("SECURECRT_BRIDGE_INVALID_RESPONSE")
        return message

    def _exchange(self, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        request_id = str(payload.get("id") or uuid.uuid4())
        message = {**payload, "id": request_id}
        self.sock.sendall((json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8"))
        while True:
            response = self._receive(timeout)
            if str(response.get("id") or "") != request_id:
                continue
            if response.get("type") == "error":
                raise SecureCRTBridgeError(
                    str(response.get("code") or "SECURECRT_BRIDGE_ERROR"),
                    str(response.get("message") or ""),
                )
            return response

    def request(self, payload: dict[str, Any], timeout: float = 10) -> dict[str, Any]:
        with self._lock:
            return self._exchange(payload, timeout)

    def list_sessions(self) -> list[dict[str, Any]]:
        return list(self.request({"type": "list_sessions"}, 5).get("sessions") or [])

    def reserve(
        self, *, project_session_id: str, asset_id: int,
        baseline_session_ids: set[str], expected_address: str = "",
        expected_username: str = "", expires_in_ms: int = 120_000,
        launch_clock_skew_ms: int = 2_000, candidate_margin_ms: int = 2_000,
        reclaim: bool = False,
    ) -> str:
        """Remember the launch baseline; no reservation is sent to the bridge."""
        del (expected_address, expected_username, expires_in_ms,
             launch_clock_skew_ms, candidate_margin_ms, reclaim)
        reservation_id = "baseline-" + uuid.uuid4().hex
        self._baselines[reservation_id] = {str(sid) for sid in baseline_session_ids}
        del project_session_id, asset_id
        return reservation_id

    def mark_launch(self, reservation_id: str) -> dict[str, Any]:
        # Launch-time activation belonged to the removed reservation protocol.
        return {"reservationId": reservation_id, "status": "NO_RESERVATION"}

    def wait_ready(self, reservation_id: str, timeout: float = 60) -> dict[str, Any]:
        baseline = self._baselines.pop(reservation_id, set())
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            candidates = [
                item for item in self.list_sessions()
                if str(item.get("sessionId") or "") not in baseline
                and str(item.get("status") or "READY").upper() == "READY"
            ]
            if candidates:
                candidates.sort(key=lambda item: float(item.get("connectedAt") or 0), reverse=True)
                return candidates[0]
            time.sleep(0.25)
        raise SecureCRTBridgeError("SECURECRT_SESSION_DISCOVERY_TIMEOUT", "no new session appeared")

    def cancel(self, reservation_id: str) -> None:
        self._baselines.pop(reservation_id, None)

    def execute(self, session_id: str, command: str, timeout: int, *,
                terminal_mode: str = "AUTO", raw_input: bool | None = None) -> dict[str, Any]:
        with self._lock:
            request_id = str(uuid.uuid4())
            ack = self._exchange({
                "type": "exec", "id": request_id, "sessionId": session_id,
                "command": command, "timeout": timeout * 1000,
                "terminalMode": terminal_mode,
                **({"rawInput": raw_input} if raw_input is not None else {}),
            }, 10)
            if ack.get("type") != "exec_ack":
                raise SecureCRTBridgeError("SECURECRT_EXEC_ACK_INVALID")
            while True:
                result = self._receive(timeout + 5)
                if str(result.get("id") or "") != request_id:
                    continue
                if result.get("type") == "error":
                    raise SecureCRTBridgeError(
                        str(result.get("code") or "SECURECRT_EXEC_FAILED"),
                        str(result.get("message") or ""),
                    )
                if result.get("type") != "exec_result":
                    continue
                output = result.get("output") or {}
                error_code = str(result.get("errorCode") or "")
                return {
                    "output": output.get("clean") or output.get("raw") or "",
                    "exit_code": result.get("exitCode"),
                    # A missing marker/prompt is an unknown command outcome,
                    # not proof that the SecureCRT terminal disconnected.
                    "status": "unknown_outcome" if error_code in {
                        "COMMAND_OUTCOME_UNKNOWN", "BEGIN_MARKER_TIMEOUT", "END_MARKER_TIMEOUT",
                        "EXIT_CODE_INVALID", "INTERACTIVE_PROMPT_TIMEOUT", "SCREEN_READ_ERROR",
                        "SQL_READ_ERROR",
                    } else ("completed" if result.get("success") else "failed"),
                    "error_code": error_code or None,
                    "error_message": result.get("errorMessage") or None,
                }

    def close_terminal(self, session_id: str) -> None:
        self.request({"type": "close_terminal", "sessionId": session_id}, 15)

    def focus_terminal(self, session_id: str) -> None:
        self.request({"type": "focus", "sessionId": session_id}, 10)

    def close(self) -> None:
        self.sock.close()


@dataclass
class SecureCRTTerminal(Base64ShellTransfer):
    client: SecureCRTBridgeClient
    session_id: str
    reservation_id: str

    def execute(self, command: str, timeout: int = 30, *, terminal_mode: str = "AUTO") -> dict[str, Any]:
        return self.client.execute(self.session_id, command, timeout, terminal_mode=terminal_mode)

    def health(self) -> dict[str, Any]:
        try:
            session = next(
                (item for item in self.client.list_sessions()
                 if str(item.get("sessionId") or "") == self.session_id), None,
            )
        except Exception:
            return {"ok": False, "status": "bridge_unreachable"}
        # Windows are shared by the operator and the Agent now, so liveness is
        # "the bridge still knows this session and it is READY", not a role match.
        ok = bool(session and session.get("status") == "READY")
        return {"ok": ok, "status": str((session or {}).get("status") or "closed").lower()}

    def probe(self, include_shell: bool = False) -> dict[str, Any]:
        health = self.health()
        if not health["ok"] or not include_shell:
            return {**health, "hostResponsive": None}
        marker = "__ALLSRE_HEARTBEAT_" + uuid.uuid4().hex[:16] + "__"
        try:
            result = self.execute(f"printf '{marker}\\n'", 5)
            responsive = marker in str(result.get("output") or "")
            return {"ok": responsive, "status": "ready", "hostResponsive": responsive}
        except Exception:
            return {"ok": False, "status": "unresponsive", "hostResponsive": False}

    def close(self) -> None:
        try:
            self.client.close_terminal(self.session_id)
        finally:
            self.client.close()

    def focus(self) -> None:
        self.client.focus_terminal(self.session_id)
