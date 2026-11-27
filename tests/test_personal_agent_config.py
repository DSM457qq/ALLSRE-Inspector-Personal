import json
from pathlib import Path

from allsre_inspector.core.opencode_compat import OpenCodeApi
from allsre_inspector.personal.agent import LocalAgentRuntime
from allsre_inspector.personal import config as config_module
from allsre_inspector.personal.config import PersonalSettings


ROOT = Path(__file__).resolve().parents[1]


def runtime(tmp_path: Path, **opencode):
    settings = PersonalSettings(
        {
            "data_dir": str(tmp_path / "data"),
            "opencode": {
                "agent": "inspector",
                "model_thinking": False,
                "model_config": {
                    "providerId": "custom",
                    "modelId": "model",
                    "baseUrl": "https://model.example/v1",
                },
                **opencode,
            },
        },
        tmp_path / "inspector.yaml",
    )
    result = LocalAgentRuntime(settings, ROOT)
    result._api = OpenCodeApi(2, "")
    return result


def test_generated_agent_config_uses_v2_permissions_and_disables_thinking(tmp_path):
    path = runtime(tmp_path)._config_path()
    config = json.loads(path.read_text(encoding="utf-8"))
    assert config["default_agent"] == "inspector"
    assert config["plugins"] and config["skills"] and config["instructions"]
    assert {"bash", "bash_readonly", "sqlbash", "list_terminals", "save_task_file"} <= {
        rule["action"] for rule in config["permissions"]
    }
    assert config["policies"] == [
        {"action": "provider.use", "resource": "*", "effect": "deny"},
        {"action": "provider.use", "resource": "custom", "effect": "allow"},
    ]
    provider = config["providers"]["custom"]
    assert provider["models"]["model"]["settings"]["thinking"] == {"type": "disabled"}


def test_model_thinking_can_be_enabled(tmp_path):
    path = runtime(tmp_path, model_thinking=True)._config_path()
    config = json.loads(path.read_text(encoding="utf-8"))
    provider = config["providers"]["custom"]
    assert provider["models"]["model"]["settings"]["thinking"] == {"type": "enabled"}


def test_recent_session_url_uses_server_route(tmp_path):
    result = runtime(tmp_path)
    result.port = 65126
    result.url = "http://127.0.0.1:65126"
    result.process = type("Process", (), {"poll": lambda self: None})()
    result._request = lambda method, path, timeout=5: {
        "data": [
            {"id": "ses_old", "time": {"updated": 1}},
            {"id": "ses_new", "time": {"updated": 2}},
        ]
    }
    url = result.recent_session_url()
    assert url.startswith("http://127.0.0.1:65126/server/")
    assert url.endswith("/session/ses_new")


def test_save_task_file_defaults_to_desktop_allsre_files(tmp_path, monkeypatch):
    desktop = tmp_path / "Desktop"
    monkeypatch.setattr(config_module, "_desktop_dir", lambda: desktop)
    settings = PersonalSettings({}, tmp_path / "inspector.yaml")
    assert settings.file_storage_dir == desktop / "ALLSRE-files"


def test_explicit_file_storage_dir_wins(tmp_path, monkeypatch):
    monkeypatch.setattr(config_module, "_desktop_dir", lambda: tmp_path / "Desktop")
    custom = tmp_path / "custom-files"
    settings = PersonalSettings({"file_storage_dir": str(custom)}, tmp_path / "inspector.yaml")
    assert settings.file_storage_dir == custom
