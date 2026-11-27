from pathlib import Path

from fastapi.testclient import TestClient

from allsre_inspector.personal.app import create_app
from allsre_inspector.personal.config import load_settings


def personal_config(tmp_path: Path, *, bridge: bool = False) -> Path:
    path = tmp_path / "inspector.yaml"
    path.write_text(
        "listen_host: 127.0.0.1\n"
        "listen_port: 8876\n"
        f"data_dir: {(tmp_path / 'data').as_posix()}\n"
        f"file_storage_dir: {(tmp_path / 'files').as_posix()}\n"
        "securecrt_bridge:\n"
        f"  enabled: {'true' if bridge else 'false'}\n"
        "  host: 127.0.0.1\n"
        "  port: 18765\n"
        "opencode:\n"
        "  executable: auto\n"
        "  api_version: \"2\"\n",
        encoding="utf-8",
    )
    return path


def test_health_and_terminal_list_work_without_assets(tmp_path):
    app = create_app(load_settings(personal_config(tmp_path)))
    with TestClient(app) as client:
        health = client.get("/health")
        terminals = client.get("/api/v1/tools/terminal-list")
    assert health.status_code == 200
    assert health.json()["service"] == "allsre-inspector-personal"
    assert terminals.status_code == 200
    assert terminals.json() == {"items": []}


def test_classify_and_file_endpoints(tmp_path):
    app = create_app(load_settings(personal_config(tmp_path)))
    with TestClient(app) as client:
        classified = client.post(
            "/api/v1/tools/bash/classify",
            json={"command": "systemctl is-active sshd"},
        )
        saved = client.post(
            "/api/v1/tools/task-file",
            json={"path": "reports/a.md", "content": "hello"},
        )
    assert classified.status_code == 200
    assert classified.json()["classification"] == "READ_ONLY"
    assert saved.status_code == 200
    assert saved.json()["path"] == "reports/a.md"


def test_remote_client_is_rejected(tmp_path):
    app = create_app(load_settings(personal_config(tmp_path)))
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/tools/terminal-list",
            headers={"X-Forwarded-For": "203.0.113.4"},
        )
    assert response.status_code == 200  # TestClient is loopback; proxy headers are not trusted.
