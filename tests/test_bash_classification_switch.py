from pathlib import Path

from fastapi.testclient import TestClient

from allsre_inspector.personal.app import create_app
from allsre_inspector.personal.config import load_settings


def personal_config(tmp_path: Path, *, classification: bool = True) -> Path:
    path = tmp_path / "inspector.yaml"
    path.write_text(
        "listen_host: 127.0.0.1\n"
        "listen_port: 8876\n"
        f"data_dir: {(tmp_path / 'data').as_posix()}\n"
        f"file_storage_dir: {(tmp_path / 'files').as_posix()}\n"
        "securecrt_bridge:\n"
        "  enabled: false\n"
        "  host: 127.0.0.1\n"
        "  port: 18765\n"
        "agent_ui:\n"
        "  tools:\n"
        f"    bash_classification_enabled: {'true' if classification else 'false'}\n"
        "opencode:\n"
        "  executable: auto\n"
        "  api_version: \"2\"\n",
        encoding="utf-8",
    )
    return path


def test_bash_classification_enabled_by_default(tmp_path):
    settings = load_settings(personal_config(tmp_path))
    assert settings.bash_classification_enabled is True
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/tools/bash/classify",
            json={"command": "systemctl --failed"},
        )
    assert response.status_code == 200
    assert response.json()["classification"] == "READ_ONLY"


def test_bash_classification_switch_disables_approval_but_keeps_destructive_guard(tmp_path):
    settings = load_settings(personal_config(tmp_path, classification=False))
    assert settings.bash_classification_enabled is False
    app = create_app(settings)
    with TestClient(app) as client:
        classified = client.post(
            "/api/v1/tools/bash/classify",
            json={"command": "systemctl --failed"},
        )
        denied = client.post(
            "/api/v1/tools/bash",
            json={"command": "rm -rf /", "terminalId": "crt-test"},
        )
    assert classified.status_code == 200
    assert classified.json()["classification"] == "READ_ONLY"
    assert classified.json()["reason"] == "classification_disabled"
    assert denied.status_code == 403
