from pathlib import Path
from types import SimpleNamespace

import pytest

from allsre_inspector.core.errors import ServiceError
from allsre_inspector.personal.audit import PersonalAuditStore
from allsre_inspector.personal.models import TaskFileWrite, ToolCommand
from allsre_inspector.personal.tools import PersonalToolService
from allsre_inspector.services.file_service import FileStorageService


class FakeTerminals:
    def __init__(self) -> None:
        self.calls = []

    def execute_terminal(self, terminal_id, command, timeout, terminal_mode="AUTO", raw_input=None):
        self.calls.append((terminal_id, command, timeout, raw_input))
        return {"output": "ok", "exit_code": 0, "status": "completed"}


def service(tmp_path: Path):
    terminals = FakeTerminals()
    return PersonalToolService(
        terminals,
        FileStorageService(tmp_path / "files"),
        PersonalAuditStore(tmp_path / "audit.sqlite3"),
    ), terminals


def test_bash_executes_selected_securecrt_terminal(tmp_path):
    svc, terminals = service(tmp_path)
    result = svc.execute(ToolCommand(command="uname -a", terminalId="crt-1"))
    assert result["output"] == "ok"
    assert terminals.calls == [("crt-1", "uname -a", 30, False)]


def test_sqlbash_uses_raw_input(tmp_path):
    svc, terminals = service(tmp_path)
    svc.execute(ToolCommand(command="select 1 from dual", terminalId="crt-1", rawInput=True))
    assert terminals.calls[0][3] is True


def test_destructive_shell_is_rejected_before_terminal(tmp_path):
    svc, terminals = service(tmp_path)
    with pytest.raises(ServiceError, match="destructive_command_denied"):
        svc.execute(ToolCommand(command="rm -rf /", terminalId="crt-1"))
    assert terminals.calls == []


def test_save_task_file_is_confined_to_storage(tmp_path):
    svc, _ = service(tmp_path)
    result = svc.save_file(TaskFileWrite(path="reports/a.md", content="hello"))
    assert result["path"] == "reports/a.md"
    assert (tmp_path / "files" / "reports" / "a.md").read_text(encoding="utf-8") == "hello"
    with pytest.raises(ServiceError, match="path_escape"):
        svc.save_file(TaskFileWrite(path="../outside.txt", content="bad"))


def test_audit_records_classification_and_result(tmp_path):
    svc, _ = service(tmp_path)
    result = svc.execute(ToolCommand(command="uname -a", terminalId="crt-1"))
    items = svc.audits()["items"]
    assert items[0]["id"] == result["auditId"]
    assert items[0]["classification"] == "READ_ONLY"
    assert items[0]["status"] == "SUCCEEDED"
