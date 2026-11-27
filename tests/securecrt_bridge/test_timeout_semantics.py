from pathlib import Path

from allsre_inspector.securecrt_bridge.bridge_v2 import REGISTRY, Registry, Session


def test_result_timeout_reports_unknown_without_fencing_terminal(monkeypatch):
    session = Session("crt-timeout-test")
    REGISTRY.sessions[session.session_id] = session
    monkeypatch.setattr(REGISTRY, "mailbox", lambda *_args, **_kwargs: None)
    try:
        result = REGISTRY.execute(session.session_id, "sleep 99", 1000, "AUTO")
        assert result["errorCode"] == "COMMAND_OUTCOME_UNKNOWN"
        assert session.status == "READY"
        assert session.error_code == ""
    finally:
        REGISTRY.sessions.pop(session.session_id, None)


def test_marker_timeout_interrupts_and_recovers_prompt(monkeypatch):
    registry = Registry()
    session = Session("crt-recover-test")
    registry.sessions[session.session_id] = session
    calls = []

    def mailbox(_session, request, _timeout):
        calls.append(request["action"])
        if request["action"] == "EXECUTE":
            return {"success": False, "errorCode": "END_MARKER_TIMEOUT"}
        return {"success": True, "output": "^C\n[root@host ~]#"}

    monkeypatch.setattr(registry, "mailbox", mailbox)
    try:
        result = registry.execute(session.session_id, "grep -c x", 1000, "AUTO")
        assert calls == ["EXECUTE", "RECOVER_PROMPT"]
        assert result["errorCode"] == "COMMAND_INTERRUPTED_AND_RECOVERED"
        assert result["recovered"] is True
        assert session.status == "READY"
    finally:
        registry.sessions.pop(session.session_id, None)


def test_shell_keepalive_only_targets_confirmed_idle_shell(monkeypatch):
    registry = Registry(shell_keepalive_enabled=True, shell_keepalive_interval_seconds=30)
    shell = Session("crt-shell-test", observed_prompt_mode="SHELL", last_command_at=0)
    sql = Session("crt-sql-test", observed_prompt_mode="SQL", last_command_at=0)
    registry.sessions = {shell.session_id: shell, sql.session_id: sql}
    calls = []

    def shell_keepalive(sid):
        calls.append(sid)
        return {"success": True, "exitCode": 0}

    monkeypatch.setattr(registry, "shell_keepalive", shell_keepalive)
    registry.run_shell_keepalive()

    assert calls == ["crt-shell-test"]


def test_auto_mode_does_not_require_a_stored_terminal_role(monkeypatch):
    registry = Registry()
    session = Session("crt-auto-test")
    registry.sessions[session.session_id] = session
    captured = {}

    def mailbox(_session, request, _timeout):
        captured.update(request)
        return {"success": True, "output": "ok", "exitCode": 0}

    monkeypatch.setattr(registry, "mailbox", mailbox)
    try:
        result = registry.execute(session.session_id, "hostname", 1000, "AUTO")
        assert result["success"] is True
        assert captured["terminalMode"] == "AUTO"
        assert session.status == "READY"
    finally:
        registry.sessions.pop(session.session_id, None)


def test_raw_input_is_forwarded_without_terminal_mode_rejection(monkeypatch):
    registry = Registry()
    session = Session("crt-raw-test")
    registry.sessions[session.session_id] = session
    captured = {}

    def mailbox(_session, request, _timeout):
        captured.update(request)
        return {"success": True, "output": "1", "exitCode": 0}

    monkeypatch.setattr(registry, "mailbox", mailbox)
    try:
        result = registry.execute(
            session.session_id, "select 1 from dual", 1000, "SQL",
            raw_input=True,
        )
        assert result["success"] is True
        assert captured["rawInput"] is True
        assert captured["terminalMode"] == "SQL"
    finally:
        registry.sessions.pop(session.session_id, None)


def test_shell_execute_disables_terminal_pagers():
    source = (Path(__file__).resolve().parents[2] / "allsre_inspector" /
              "securecrt_bridge" / "securecrt_bridge_v2.py").read_text(encoding="utf-8")
    assert "SYSTEMD_PAGER=cat" in source
    assert "GIT_PAGER=cat" in source


def test_shell_request_disables_pagers_even_for_old_tab_script(monkeypatch):
    registry = Registry()
    session = Session("crt-pager-test")
    registry.sessions[session.session_id] = session
    captured = {}

    def mailbox(_session, request, _timeout):
        captured.update(request)
        return {"success": True, "output": "ok", "exitCode": 0}

    monkeypatch.setattr(registry, "mailbox", mailbox)
    try:
        registry.execute(session.session_id, "systemctl list-units", 1000, "AUTO",
                         raw_input=False)
        assert captured["command"].startswith("export SYSTEMD_PAGER=cat")
        assert "systemctl list-units" in captured["command"]
    finally:
        registry.sessions.pop(session.session_id, None)
