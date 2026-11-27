from __future__ import annotations

from time import monotonic
from typing import Any
import hashlib
import logging

from ..core.errors import ServiceError
from ..core.readonly_policy import classify_bash_command
from ..core.security import destructive_command_reason
from ..services.file_service import FileStorageService
from .models import TaskFileWrite, ToolCommand


LOG = logging.getLogger(__name__)


class PersonalToolService:
    """Terminal and local-file tools without assets, tasks or ConfigCenter."""

    def __init__(self, terminals: Any, files: FileStorageService, audit: Any,
                 *, bash_classification_enabled: bool = True) -> None:
        self._terminals = terminals
        self._files = files
        self._audit = audit
        self.bash_classification_enabled = bool(bash_classification_enabled)
        if not self.bash_classification_enabled:
            LOG.warning(
                "bash classification DISABLED via agent_ui.tools."
                "bash_classification_enabled=false; destructive commands remain blocked"
            )

    @staticmethod
    def _summary(command: str) -> str:
        return " ".join(command.strip().split())[:200]

    def execute(self, body: ToolCommand) -> dict[str, Any]:
        command = str(body.command or "").strip()
        if not command:
            raise ServiceError(422, "command_required", {"code": "command_required"})
        is_raw = body.rawInput is True
        destructive = None if is_raw else destructive_command_reason(command)
        if destructive:
            raise ServiceError(403, "destructive_command_denied", {"code": destructive})
        classification = str(body.classification or "").upper()
        if not self.bash_classification_enabled:
            # Break-glass mode: the plugin must receive READ_ONLY from
            # /bash/classify so it does not ask for every command.  The
            # irreversible-command guard above still runs independently.
            classification = "READ_ONLY"
        elif classification not in {"READ_ONLY", "MUTATING", "DESTRUCTIVE"}:
            classification = str(classify_bash_command(command)["classification"])
        audit_id = self._audit.create({
            "command_hash": hashlib.sha256(command.encode("utf-8")).hexdigest(),
            "command_summary": self._summary(command),
            "classification": classification,
        })
        started = monotonic()
        try:
            result = self._terminals.execute_terminal(
                body.terminalId, command, int(body.timeout),
                raw_input=True if is_raw else False,
            )
            error_code = str(result.get("error_code") or "")
            status = str(result.get("status") or "")
            audit_status = ("OUTCOME_UNKNOWN" if status == "unknown_outcome"
                            else "SUCCEEDED" if result.get("exit_code") == 0
                            else "FAILED")
            self._audit.finish(
                audit_id, status=audit_status,
                exit_code=result.get("exit_code"),
                duration_ms=int((monotonic() - started) * 1000),
            )
            return {
                **result,
                "ok": status != "failed",
                "auditId": audit_id,
                "classification": classification,
                **({"errorCode": error_code} if error_code else {}),
            }
        except Exception:
            self._audit.finish(
                audit_id, status="FAILED",
                duration_ms=int((monotonic() - started) * 1000),
            )
            raise

    def save_file(self, body: TaskFileWrite) -> dict[str, Any]:
        result = self._files.write_text(body.path, body.content)
        return {"ok": True, **result}

    def audits(self, limit: int = 100) -> dict[str, Any]:
        return {"items": self._audit.list(limit)}
