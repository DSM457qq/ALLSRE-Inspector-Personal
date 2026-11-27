from __future__ import annotations

from typing import Any
import subprocess


class ServiceError(RuntimeError):
    def __init__(self, status_code: int, code: str, detail: Any | None = None) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.detail = detail if detail is not None else code


class TaskCancelled(RuntimeError):
    pass


class TaskTimedOut(RuntimeError):
    pass


class VpnComponentInitializationDetected(RuntimeError):
    """A VPN client native "initializing" window appeared during login.

    Raised by the orchestrator's cancel_check when the observer sees the
    EasyConnect/aTrust initialization window.  Must propagate through the
    recording-replay and Browser-Agent layers unswallowed so the caller can
    wait for the window to disappear and restart the login from scratch.
    """


def error_type(exc: BaseException) -> str:
    """Best-effort hierarchical error code ({category}.{subtype}) for an exception.

    Used by the phase timeline to categorize failures. ``raw_exception`` (the
    class name) is logged alongside for exact traceability.
    """
    if isinstance(exc, ServiceError):
        return f"service.{str(exc.code).lower()}"
    if isinstance(exc, TaskCancelled):
        return "task.cancelled"
    if isinstance(exc, TaskTimedOut):
        return "task.timeout"

    code = getattr(exc, "workflow_code", None)
    if code:
        return f"workflow.{code}"

    name = type(exc).__name__.lower()
    text = str(exc).lower()

    if text.startswith("vpn_process_enumeration_timeout"):
        return "system.process_enumeration_timeout"
    if isinstance(exc, subprocess.TimeoutExpired):
        command = exc.cmd
        program = command[0] if isinstance(command, (list, tuple)) and command else command
        if str(program).casefold() in {"tasklist", "tasklist.exe"}:
            return "system.process_enumeration_timeout"
    if "timeout" in name or "timedout" in name:
        return "network.timeout"
    if "connectionrefused" in name.replace("_", "") or "connection refused" in text:
        return "network.connection_refused"
    if "connection" in name:
        return "network.connection_error"

    # Message-prefix errors introduced elsewhere (kept stable for grouping).
    for prefix, cat in (
        ("browser_opencode_exited", "browser.opencode_exited"),
        ("browser_agent_inactivity_timeout", "agent.inactivity_timeout"),
        ("browser_agent_ended_without_result", "agent.no_result"),
        ("vpn_disconnect_not_confirmed", "vpn.disconnect_not_confirmed"),
        ("vpn_login_process_not_found", "vpn.process_not_found"),
        ("recording_operation_unsupported", "recording.unsupported_op"),
    ):
        if text.startswith(prefix):
            return cat

    # Plain RuntimeErrors in this codebase carry a "code[:detail]" message
    # (e.g. "inspection_skill_not_loaded:ses_..."). Surface the leading code so
    # the timeline stays greppable instead of collapsing to "error.runtime_error".
    head = str(exc).split(":", 1)[0].strip()
    if head and all(c.isalnum() or c in "_-." for c in head) and not head[0].isdigit():
        return f"error.{head.lower()}"

    snake = "".join("_" + ch.lower() if ch.isupper() else ch for ch in type(exc).__name__).lstrip("_")
    return f"error.{snake}"
