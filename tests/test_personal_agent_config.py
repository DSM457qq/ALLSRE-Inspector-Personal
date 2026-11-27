import json
from pathlib import Path

from allsre_inspector.core.opencode_compat import OpenCodeApi
from allsre_inspector.personal.agent import LocalAgentRuntime
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
    provider = config["providers"]["custom"]
    assert provider["models"]["model"]["settings"]["thinking"] == {"type": "disabled"}


def test_model_thinking_can_be_enabled(tmp_path):
    path = runtime(tmp_path, model_thinking=True)._config_path()
    config = json.loads(path.read_text(encoding="utf-8"))
    provider = config["providers"]["custom"]
    assert provider["models"]["model"]["settings"]["thinking"] == {"type": "enabled"}
