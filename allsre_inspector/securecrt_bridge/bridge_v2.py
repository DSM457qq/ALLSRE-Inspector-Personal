#!/usr/bin/env python3
"""Authenticated local bridge for ALLSRE-controlled SecureCRT tabs."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import secrets
import socket
import threading
import time
import uuid
from typing import Any

HOST = "127.0.0.1"
PORT = int(os.environ.get("ALLSRE_SECURECRT_BRIDGE_PORT", "8765"))
ROOT = Path(__file__).resolve().parent
IPC = ROOT / "ipc-v2"
TOKEN_FILE = ROOT / "bridge.token"
MAX_MESSAGE = 1024 * 1024
MAX_COMMAND = 32768
MAX_TIMEOUT = 3600
LOCK = threading.RLock()


def timestamp() -> float:
    return time.time()


def ensure_dirs() -> None:
    for name in ("sessions", "requests", "results", "bindings", "quarantine"):
        (IPC / name).mkdir(parents=True, exist_ok=True)


def load_token() -> str:
    configured = os.environ.get("ALLSRE_SECURECRT_BRIDGE_TOKEN", "").strip()
    if configured:
        return configured
    if not TOKEN_FILE.exists():
        temporary = TOKEN_FILE.with_suffix(".tmp")
        temporary.write_text(secrets.token_urlsafe(48), encoding="ascii")
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, TOKEN_FILE)
    token = TOKEN_FILE.read_text(encoding="ascii").strip()
    if len(token) < 32:
        raise RuntimeError("bridge token must contain at least 32 characters")
    return token


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def write_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, path)


def remove(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


class BridgeError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class Session:
    session_id: str
    address: str = ""
    username: str = ""
    port: int = 22
    connected_at: float = 0
    last_seen_at: float = 0
    connected: bool = True
    screen_state: str = "SYNCHRONIZED"
    status: str = "READY"
    # The bridge cannot safely infer an interactive program from a silent
    # screen.  In particular, a missing prompt does not mean SSH has died.
    # Mode changes are therefore operator-confirmed rather than guessed from
    # a command result.
    observed_prompt_mode: str = "UNKNOWN"
    busy_until: float = 0
    last_command_at: float = 0
    reservation_id: str = ""
    project_session_id: str = ""
    asset_id: int | None = None
    error_code: str = ""
    command_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def output(self) -> dict[str, Any]:
        return {
            "sessionId": self.session_id, "address": self.address,
            "username": self.username, "port": self.port,
            "connectedAt": self.connected_at, "lastSeenAt": self.last_seen_at,
            "connected": self.connected, "screenState": self.screen_state,
            "status": self.status,
            "observedPromptMode": self.observed_prompt_mode,
            "reservationId": self.reservation_id or None,
            "projectSessionId": self.project_session_id or None,
            "assetId": self.asset_id, "errorCode": self.error_code or None,
        }


class Registry:
    def __init__(self, *, shell_keepalive_enabled: bool = False,
                 shell_keepalive_interval_seconds: float = 90) -> None:
        self.sessions: dict[str, Session] = {}
        self.stopping = threading.Event()
        self.shell_keepalive_enabled = bool(shell_keepalive_enabled)
        self.shell_keepalive_interval_seconds = max(30.0, float(shell_keepalive_interval_seconds))

    def scan(self) -> None:
        current = timestamp()
        with LOCK:
            for path in (IPC / "sessions").glob("*.json"):
                raw = read_json(path)
                if not raw:
                    continue
                sid = str(raw.get("sessionId") or raw.get("session_id") or "")
                if not re.fullmatch(r"crt-[A-Za-z0-9-]{4,80}", sid):
                    continue
                item = self.sessions.setdefault(sid, Session(sid, last_command_at=current))
                item.address = str(raw.get("address") or "")
                item.username = str(raw.get("username") or "")
                item.port = int(raw.get("port") or 22)
                item.connected_at = float(raw.get("connectedAt") or raw.get("connected_at") or current)
                item.last_seen_at = float(raw.get("lastSeenAt") or raw.get("last_seen") or 0)
                item.connected = bool(raw.get("connected", True))
                item.screen_state = str(raw.get("screenState") or "SYNCHRONIZED")
                observed = str(raw.get("observedPromptMode") or "UNKNOWN").upper()
                item.observed_prompt_mode = observed if observed in {
                    "SHELL", "SQL", "INTERACTIVE", "UNKNOWN",
                } else "UNKNOWN"
                # A stale bridge version may have left the session in the old
                # terminal-wide OUTCOME_UNKNOWN state.  A fresh heartbeat
                # with a visible prompt proves the tab is available for the
                # next input, even if a previous result was not captured.
                if item.status == "OUTCOME_UNKNOWN" and item.connected and item.observed_prompt_mode in {
                    "SHELL", "SQL",
                }:
                    item.status, item.error_code = "READY", ""
            closed: list[str] = []
            for sid, item in self.sessions.items():
                age = current - item.last_seen_at
                # The SecureCRT tab script is single-threaded: while it is
                # waiting for a foreground command it cannot write its normal
                # two-second heartbeat.  Keep that tab registered through the
                # requested command deadline instead of misclassifying a
                # quiet/long-running command as a dropped connection.
                command_still_allowed = item.status == "BUSY" and current <= item.busy_until
                if (age > 8 and not command_still_allowed) or not item.connected:
                    closed.append(sid)
            # Registry semantics: a closed window disappears from the list.
            for sid in closed:
                self.sessions.pop(sid, None)
                remove(IPC / "sessions" / f"{sid}.json")

    def scan_loop(self) -> None:
        while not self.stopping.wait(0.25):
            self.scan()
            self.run_shell_keepalive()

    def run_shell_keepalive(self) -> None:
        """Keep an *idle, visibly detected Shell* session alive without touching SQL.

        The no-op is deliberately never sent to UNKNOWN/SQL/BUSY terminals.
        It uses the same per-terminal lock as Agent input.  An unobserved
        result is returned to that keepalive attempt only; it never fences a
        live terminal from subsequent operator or Agent commands.
        """
        if not self.shell_keepalive_enabled:
            return
        now = timestamp()
        with LOCK:
            candidates = [
                item.session_id for item in self.sessions.values()
                if item.status == "READY" and item.observed_prompt_mode == "SHELL"
                and now - item.last_command_at >= self.shell_keepalive_interval_seconds
            ]
        for sid in candidates:
            try:
                self.shell_keepalive(sid)
            except BridgeError:
                # A concurrent Agent call, a mode change, or a failed/noisy
                # heartbeat must never be retried by this scheduler.
                continue

    def shell_keepalive(self, sid: str) -> dict[str, Any]:
        """Ask the tab script to re-check the prompt then run ``:`` if safe."""
        with LOCK:
            session = self.sessions.get(sid)
            if not session:
                raise BridgeError("TERMINAL_NOT_FOUND", "session not found")
            if session.status != "READY" or session.observed_prompt_mode != "SHELL":
                raise BridgeError("SHELL_PROMPT_NOT_OBSERVED", "terminal is not at an idle Shell prompt")
        if not session.command_lock.acquire(blocking=False):
            raise BridgeError("TERMINAL_BUSY", "another command is running")
        try:
            with LOCK:
                session.status = "BUSY"
                session.busy_until = timestamp() + 15
                session.last_command_at = timestamp()
            request = {
                "schemaVersion": 2, "requestId": "req-" + uuid.uuid4().hex,
                "sessionId": sid, "action": "SHELL_KEEPALIVE", "keepalive": True,
                "timeoutSeconds": 5, "createdAt": timestamp(), "expiresAt": timestamp() + 10,
            }
            result = self.mailbox(session, request, 10)
            with LOCK:
                session.busy_until = 0
                session.last_command_at = timestamp()
                if result is None or result.get("errorCode") in {
                    "BEGIN_MARKER_TIMEOUT", "END_MARKER_TIMEOUT", "EXIT_CODE_INVALID",
                    "SCREEN_READ_ERROR",
                }:
                    session.status, session.error_code = "READY", ""
                else:
                    session.status = "READY"
                    # A changed/non-Shell prompt is an intentional skip, not a
                    # failed connection or a reason to retry immediately.
                    session.error_code = ""
            return result or {"success": False, "errorCode": "COMMAND_OUTCOME_UNKNOWN"}
        finally:
            session.command_lock.release()

    def mailbox(self, session: Session, request: dict[str, Any], timeout: float) -> dict[str, Any] | None:
        request_dir = IPC / "requests" / session.session_id
        request_dir.mkdir(parents=True, exist_ok=True)
        request_id = str(request["requestId"])
        request_path = request_dir / f"{request_id}.json"
        result_path = IPC / "results" / f"{request_id}.json"
        write_json(request_path, request)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = read_json(result_path)
            if result and str(result.get("requestId") or result.get("request_id")) == request_id:
                remove(result_path)
                return result
            time.sleep(0.05)
        remove(request_path)
        return None

    def execute(self, sid: str, command: str, timeout_ms: int,
                terminal_mode: str = "AUTO", *,
                raw_input: bool | None = None,
                is_keepalive: bool = False) -> dict[str, Any]:
        with LOCK:
            session = self.sessions.get(sid)
            if not session:
                raise BridgeError("TERMINAL_NOT_FOUND", "session not found")
            if session.status != "READY":
                raise BridgeError("TERMINAL_NOT_READY", f"terminal status is {session.status}")
            # terminalMode is retained only as a legacy compatibility hint.
            # It never selects or persists a terminal type; rawInput controls
            # whether this one command is wrapped.
        if len(command.encode("utf-8")) > MAX_COMMAND:
            raise BridgeError("COMMAND_TOO_LARGE", "command exceeds 32 KB")
        # Disable pagers at the request layer as well as in the tab script.
        # Existing SecureCRT tabs may still run an older script until they are
        # reopened; the prefix travels with the command and therefore fixes
        # those tabs without requiring a tab restart.
        if not (raw_input is True or
                (raw_input is None and str(terminal_mode or "AUTO").upper() == "SQL")):
            command = "export SYSTEMD_PAGER=cat PAGER=cat GIT_PAGER=cat; " + command
            if len(command.encode("utf-8")) > MAX_COMMAND:
                raise BridgeError("COMMAND_TOO_LARGE", "command exceeds 32 KB")
        if not session.command_lock.acquire(blocking=False):
            raise BridgeError("TERMINAL_BUSY", "another command is running")
        try:
            timeout = max(1, min(MAX_TIMEOUT, (int(timeout_ms) + 999) // 1000))
            with LOCK:
                session.status = "BUSY"
                session.busy_until = timestamp() + timeout + 10
                session.last_command_at = timestamp()
            request = {"schemaVersion": 2, "requestId": "req-" + uuid.uuid4().hex,
                       "sessionId": sid, "action": "EXECUTE", "command": command,
                       "terminalMode": terminal_mode,
                       **({"rawInput": raw_input} if raw_input is not None else {}),
                       "keepalive": bool(is_keepalive),
                       "timeoutSeconds": timeout, "createdAt": timestamp(),
                       "expiresAt": timestamp() + timeout + 5}
            result = self.mailbox(session, request, timeout + 5)
            if result is None:
                with LOCK:
                    # A command may still be running, be waiting at a pager,
                    # or have produced output the screen reader did not see.
                    # Report that invocation as unknown, but do not fence the
                    # terminal: its next visible prompt/command remains the
                    # authoritative state.
                    session.status, session.error_code = "READY", ""
                    session.busy_until = 0
                return {
                    "success": False, "output": "", "exitCode": None,
                    "errorCode": "COMMAND_OUTCOME_UNKNOWN",
                    "errorMessage": "command result was not observed; terminal remains connected",
                }
            if str(result.get("errorCode") or "") in {
                "BEGIN_MARKER_TIMEOUT", "END_MARKER_TIMEOUT", "EXIT_CODE_INVALID",
                "INTERACTIVE_PROMPT_TIMEOUT", "SCREEN_READ_ERROR", "SQL_READ_ERROR",
            }:
                # The tab script has returned to its mailbox loop at this point,
                # so it is safe to submit an explicit recovery request. Never
                # retry the original command: it may already have run.
                recovered = self._recover_prompt(session)
                if recovered:
                    result = dict(result)
                    result["recovered"] = True
                    result["recoveryAction"] = "CTRL_C"
                    result["errorCode"] = "COMMAND_INTERRUPTED_AND_RECOVERED"
                    result["errorMessage"] = (
                        "command outcome was not captured; Ctrl+C restored an interactive prompt; "
                        "do not retry the original command automatically"
                    )
            with LOCK:
                # A marker/prompt read failure describes this invocation, not
                # the terminal's ability to accept its next command.  Keep
                # the per-invocation error in ``result`` and leave the tab
                # available; otherwise a harmless output-capture miss blocks
                # an already returned SQL prompt indefinitely.
                session.status, session.error_code = "READY", ""
                session.busy_until = 0
                session.last_command_at = timestamp()
            return result
        finally:
            session.command_lock.release()

    def _recover_prompt(self, session: Session) -> bool:
        request = {
            "schemaVersion": 2, "requestId": "req-" + uuid.uuid4().hex,
            "sessionId": session.session_id, "action": "RECOVER_PROMPT",
            "timeoutSeconds": 8, "createdAt": timestamp(), "expiresAt": timestamp() + 10,
        }
        try:
            result = self.mailbox(session, request, 10)
        except Exception:
            return False
        return bool(result and result.get("success"))

    def focus(self, sid: str) -> dict[str, Any]:
        with LOCK:
            session = self.sessions.get(sid)
            if not session:
                raise BridgeError("TERMINAL_NOT_FOUND", "session not found")
            if session.status != "READY":
                raise BridgeError("TERMINAL_NOT_READY", f"terminal status is {session.status}")
        request = {"schemaVersion": 2, "requestId": "req-" + uuid.uuid4().hex,
                   "sessionId": sid, "action": "FOCUS", "createdAt": timestamp(),
                   "expiresAt": timestamp() + 10}
        result = self.mailbox(session, request, 10)
        if result is None:
            raise BridgeError("TERMINAL_FOCUS_TIMEOUT", "SecureCRT focus result timeout")
        # SecureCRT's mailbox script returns the v2 result shape from
        # ``response()``: success/errorMessage.  ``ok`` is only the outer TCP
        # bridge acknowledgement and is never present in this mailbox result.
        if not result.get("success", False):
            raise BridgeError(str(result.get("errorCode") or "TERMINAL_FOCUS_FAILED"),
                              str(result.get("errorMessage") or ""))
        return result

REGISTRY = Registry()


def send(sock: socket.socket, value: dict[str, Any]) -> bool:
    try:
        sock.sendall((json.dumps(value, ensure_ascii=False) + "\n").encode("utf-8"))
        return True
    except OSError:
        return False


def read_line(sock: socket.socket) -> bytes | None:
    value = bytearray()
    while len(value) <= MAX_MESSAGE:
        char = sock.recv(1)
        if not char:
            return None
        if char == b"\n":
            return bytes(value)
        value.extend(char)
    raise BridgeError("MESSAGE_TOO_LARGE", "message exceeds 1 MB")


def dispatch(sock: socket.socket, message: dict[str, Any]) -> None:
    request_id = str(message.get("id") or uuid.uuid4())
    kind = str(message.get("type") or "")
    if kind == "ping":
        send(sock, {"type": "pong", "id": request_id, "time": timestamp()})
    elif kind == "capabilities":
        send(sock, {"type": "capabilities", "id": request_id, "protocolVersion": 2,
                    "features": ["registry", "exec", "focus", "prompt_detection"]})
    elif kind == "list_sessions":
        REGISTRY.scan()
        with LOCK:
            sessions = [s.output() for s in REGISTRY.sessions.values() if s.status != "CLOSED"]
        send(sock, {"type": "session_list", "id": request_id, "sessions": sessions})
    elif kind == "exec":
        send(sock, {"type": "exec_ack", "id": request_id})
        result = REGISTRY.execute(str(message.get("sessionId") or ""),
                                  str(message.get("command") or ""),
                                  int(message.get("timeout") or 30000),
                                  str(message.get("terminalMode") or "AUTO"))
        output = str(result.get("output") or "")
        send(sock, {"type": "exec_result", "id": request_id,
                    "sessionId": message.get("sessionId"),
                    "output": {"raw": output, "clean": output},
                    "exitCode": result.get("exitCode"), "success": result.get("success"),
                    "trigger": "marker", "errorCode": result.get("errorCode"),
                    "errorMessage": result.get("errorMessage")})
    elif kind == "focus":
        result = REGISTRY.focus(str(message.get("sessionId") or ""))
        send(sock, {"type": "focus_result", "id": request_id,
                    "sessionId": message.get("sessionId"), "ok": True,
                    "result": result})
    elif kind == "close_terminal":
        sid = str(message.get("sessionId") or "")
        with LOCK:
            session = REGISTRY.sessions.get(sid)
        if session is not None:
            request = {"schemaVersion": 2, "requestId": "req-" + uuid.uuid4().hex,
                       "sessionId": sid, "action": "STOP", "createdAt": timestamp(),
                       "expiresAt": timestamp() + 10}
            try:
                REGISTRY.mailbox(session, request, 10)
            except Exception:
                pass
            with LOCK:
                REGISTRY.sessions.pop(sid, None)
            remove(IPC / "sessions" / f"{sid}.json")
            remove(IPC / "bindings" / f"{sid}.json")
        send(sock, {"type": "terminal_closed", "id": request_id, "closed": True})
    else:
        raise BridgeError("UNKNOWN_ACTION", f"unsupported request type: {kind}")


def client_loop(sock: socket.socket, token: str) -> None:
    message: dict[str, Any] = {}
    try:
        sock.settimeout(20)
        first = read_line(sock)
        if first is None:
            return
        auth = json.loads(first.decode("utf-8"))
        if not isinstance(auth, dict) or auth.get("type") != "authenticate" \
                or not secrets.compare_digest(str(auth.get("token") or ""), token):
            send(sock, {"type": "error", "code": "BRIDGE_AUTH_FAILED",
                        "message": "authentication required"})
            return
        send(sock, {"type": "authenticated", "id": auth.get("id"), "protocolVersion": 2})
        sock.settimeout(300)
        while True:
            raw = read_line(sock)
            if raw is None:
                return
            message = json.loads(raw.decode("utf-8"))
            if not isinstance(message, dict):
                raise BridgeError("INVALID_MESSAGE", "JSON object required")
            try:
                dispatch(sock, message)
            except BridgeError as error:
                send(sock, {"type": "error", "id": message.get("id"),
                            "code": error.code, "message": str(error)})
    except (OSError, ValueError, UnicodeDecodeError, BridgeError):
        pass
    finally:
        sock.close()


def cleanup_loop() -> None:
    while not REGISTRY.stopping.wait(60):
        cutoff = timestamp() - 86400
        for directory in ("requests", "results", "quarantine"):
            for path in (IPC / directory).rglob("*.json"):
                try:
                    if path.stat().st_mtime < cutoff:
                        path.unlink()
                except OSError:
                    pass


def main(*, host: str = HOST, port: int = PORT,
         stop_event: threading.Event | None = None,
         ready_event: threading.Event | None = None) -> None:
    ensure_dirs()
    token = load_token()
    if stop_event is not None:
        REGISTRY.stopping = stop_event
    threading.Thread(target=REGISTRY.scan_loop, daemon=True).start()
    threading.Thread(target=cleanup_loop, daemon=True).start()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        server.bind((host, port))
        server.listen(32)
        server.settimeout(0.25)
        print(f"ALLSRE SecureCRT Bridge v2 listening on {host}:{port}", flush=True)
        if ready_event is not None:
            ready_event.set()
        while not REGISTRY.stopping.is_set():
            try:
                client, _ = server.accept()
            except socket.timeout:
                continue
            threading.Thread(target=client_loop, args=(client, token), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        REGISTRY.stopping.set()
        server.close()


if __name__ == "__main__":
    main()
