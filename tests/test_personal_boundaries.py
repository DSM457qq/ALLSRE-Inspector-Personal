from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "allsre_inspector"


def test_no_browser_or_asset_modules_are_shipped():
    forbidden = (
        "browser_agent", "capabilities/agents/browser", "connectors/browser",
        "services/browser_", "services/chrome_profile_baseline",
        "services/task_", "services/worker_", "services/project_session",
        "services/ansible_", "services/recording_",
    )
    found = []
    for path in PACKAGE.rglob("*"):
        text = path.as_posix()
        if any(item in text for item in forbidden):
            found.append(text)
    assert found == []


def test_plugin_has_no_asset_or_sftp_tools():
    source = (ROOT / ".opencode" / "plugins" / "allsre-tools" / "index.ts").read_text(encoding="utf-8")
    for name in ("sftp_upload", "sftp_download", "submit_task_result", "assetId"):
        assert name not in source
    for name in ("bash", "sqlbash", "list_terminals", "save_task_file"):
        assert f'name: "{name}"' in source


def test_console_agent_button_uses_pairing_route():
    source = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    assert "window.location.href = '/agent'" in source
    assert "window.location.href = v.url" not in source
