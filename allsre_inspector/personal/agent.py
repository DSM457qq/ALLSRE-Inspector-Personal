from __future__ import annotations

from pathlib import Path
from threading import Lock
from typing import Any
import base64
import json
import os
import secrets
import shutil
import socket
import subprocess
import time
import urllib.parse
import urllib.request

from ..core.executables import resolve_opencode_executable
from ..core.opencode_compat import OpenCodeApi, detect_opencode_major


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class LocalAgentRuntime:
    """One generic OpenCode V2 server with Inspector's local tools."""

    def __init__(self, settings: Any, project_root: Path, *, service_token: str = "") -> None:
        self.settings = settings
        self.project_root = project_root
        self.service_token = service_token
        self.process: subprocess.Popen[Any] | None = None
        self.port: int | None = None
        self.url = ""
        self._lock = Lock()
        self._api = OpenCodeApi()

    @property
    def running(self) -> bool:
        return bool(self.process is not None and self.process.poll() is None and self.port)

    def _config_path(self) -> Path:
        data = self.settings.data_dir
        data.mkdir(parents=True, exist_ok=True)
        base = json.loads((self.project_root / "opencode.json").read_text(encoding="utf-8"))
        opencode = self.settings.opencode
        model_config = dict(opencode.get("model_config") or {})
        thinking = {
            "type": "enabled" if bool(opencode.get("model_thinking", False)) else "disabled",
        }
        agent = str(opencode.get("agent") or "inspector")
        if agent in dict(base.get("agents") or {}):
            base["default_agent"] = agent
        if model_config.get("baseUrl") and model_config.get("modelId"):
            provider_id = str(model_config.get("providerId") or "custom")
            model_id = str(model_config["modelId"])
            base["model"] = f"{provider_id}/{model_id}"
            provider = {
                "package": "aisdk:@ai-sdk/openai-compatible",
                "name": provider_id,
                "settings": {
                    "baseURL": str(model_config["baseUrl"]).rstrip("/"),
                    "apiKey": "{env:ALLSRE_PERSONAL_MODEL_API_KEY}",
                },
                "models": {
                    model_id: {
                        "name": model_id,
                        "capabilities": {
                            "tools": True, "input": ["text", "image"], "output": ["text"],
                        },
                        "settings": {"thinking": thinking},
                    }
                },
            }
            if self._api.v2:
                base.pop("provider", None)
                base["providers"] = {provider_id: provider}
                # V2's supported model filter is the provider.use policy.
                # Built-in free catalog providers are denied, while the one
                # configured provider is selectable.
                base["policies"] = [
                    {"action": "provider.use", "resource": "*", "effect": "deny"},
                    {"action": "provider.use", "resource": provider_id, "effect": "allow"},
                ]
            else:
                base.setdefault("provider", {})[provider_id] = {
                    "npm": "@ai-sdk/openai-compatible",
                    "name": provider_id,
                    "options": provider["settings"],
                    "models": {model_id: {"name": model_id, "options": {"thinking": thinking}}},
                }
        plugin = (self.project_root / ".opencode" / "plugins" / "allsre-tools").resolve()
        skills = (self.project_root / ".opencode" / "skills").resolve()
        instructions = (self.project_root / "prompts" / "agent-ui.md").resolve()
        base["plugins"] = [str(plugin)]
        base["skills"] = [str(skills)]
        base["instructions"] = [str(instructions)]
        base["permissions"] = [
            {"action": "*", "resource": "*", "effect": "deny"},
            {"action": "bash", "resource": "*", "effect": "ask"},
            {"action": "bash_readonly", "resource": "*", "effect": "allow"},
            {"action": "bash_destructive", "resource": "*", "effect": "deny"},
            {"action": "sqlbash", "resource": "*", "effect": "allow"},
            {"action": "list_terminals", "resource": "*", "effect": "allow"},
            {"action": "save_task_file", "resource": "*", "effect": "allow"},
            {"action": "skill", "resource": "linux-host-inspection", "effect": "allow"},
            {"action": "skill", "resource": "incident-troubleshooting", "effect": "allow"},
        ]
        path = data / "opencode-personal.runtime.json"
        path.write_text(json.dumps(base, ensure_ascii=False, indent=2), encoding="utf-8")
        return path.resolve()

    def start(self) -> dict[str, Any]:
        with self._lock:
            if self.running:
                return self.status()
            configured = str(self.settings.opencode.get("executable") or "opencode")
            executable = shutil.which(configured) or resolve_opencode_executable(configured)
            if executable and Path(executable).suffix.lower() in {".cmd", ".ps1"}:
                executable = resolve_opencode_executable(executable) or executable
            if not executable:
                raise RuntimeError("opencode_not_found")
            self.port = _free_port()
            self._api = OpenCodeApi(
                detect_opencode_major(executable, self.settings.opencode.get("api_version", "2")),
                secrets.token_urlsafe(32),
            )
            env = os.environ.copy()
            env["ALLSRE_INSPECTOR_API_BASE"] = f"http://127.0.0.1:{self.settings.port}"
            env["ALLSRE_INSPECTOR_TOOL_TOKEN"] = self.service_token
            # Keep OpenCode's free catalog out of the model picker.  The
            # configured provider is the only one exposed by the generated
            # provider.use policy as well.
            env["OPENCODE_DISABLE_FREE_MODELS"] = "1"
            env["ALLSRE_PERSONAL_MODEL_API_KEY"] = str(
                (self.settings.opencode.get("model_config") or {}).get("apiKey") or ""
            )
            env["OPENCODE_CONFIG"] = str(self._config_path())
            env["OPENCODE_DISABLE_PROJECT_CONFIG"] = "1"
            if self._api.v2:
                env["OPENCODE_PASSWORD"] = self._api.password
            log_path = self.settings.data_dir / "opencode-personal.log"
            log = log_path.open("ab")
            command = [executable, "serve", "--hostname", "127.0.0.1", "--port", str(self.port)]
            self.process = subprocess.Popen(
                command, cwd=self.project_root, env=env,
                stdout=log, stderr=subprocess.STDOUT,
            )
            deadline = time.monotonic() + float(self.settings.opencode.get("startup_timeout") or 30)
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError(f"opencode_exited:{self.process.returncode}")
                try:
                    self._request("GET", "/global/health", timeout=2)
                    self.url = f"http://127.0.0.1:{self.port}"
                    return self.status()
                except Exception:
                    time.sleep(0.25)
            self.stop()
            raise TimeoutError("opencode_start_timeout")

    def _request(self, method: str, path: str, *, timeout: float = 5) -> dict[str, Any]:
        url = f"http://127.0.0.1:{self.port}{self._api.path(method, path)}"
        request = urllib.request.Request(url, method=method, headers=self._api.headers())
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8") or "{}")

    def recent_session_url(self) -> str:
        """Return the OpenCode URL for the most recently updated session."""
        if not self.running or not self.port:
            raise RuntimeError("local_agent_not_running")
        value = self._request("GET", "/session", timeout=5)
        items = value.get("data") if isinstance(value, dict) else value
        if not isinstance(items, list):
            items = []
        sessions = [item for item in items if isinstance(item, dict) and str(item.get("id") or "").startswith("ses_")]
        if not sessions:
            return self.url
        def stamp(item: dict[str, Any]) -> float:
            time_value = item.get("time") if isinstance(item.get("time"), dict) else {}
            for candidate in (item.get("updatedAt"), item.get("createdAt"),
                              time_value.get("updated"), time_value.get("created")):
                try:
                    return float(candidate)
                except (TypeError, ValueError):
                    continue
            return 0.0
        session = max(sessions, key=stamp)
        session_id = str(session.get("id"))
        # OpenCode V2 browser route is /server/<base64url(server-origin)>/session/<id>.
        server = f"http://127.0.0.1:{self.port}"
        encoded = base64.urlsafe_b64encode(server.encode("utf-8")).decode("ascii").rstrip("=")
        return f"{server}/server/{encoded}/session/{session_id}"

    def pair_cookie(self) -> tuple[str, str]:
        """Redeem a pairing code server-side and return (target, Set-Cookie).

        The browser cannot set a second-origin cookie from an iframe reliably
        (SameSite/third-party cookie policy).  Inspector runs on the same host,
        so it can redeem the one-time code itself and hand the resulting
        OpenCode session cookie to the browser in the redirect response.
        """
        if not self.running or not self.port:
            raise RuntimeError("local_agent_not_running")
        pair = self._request("POST", "/api/pair", timeout=5)
        code = str(pair.get("code") or "")
        if not code:
            raise RuntimeError("local_agent_pair_failed")
        import http.client
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(
                "GET",
                "/auth/connect/" + urllib.parse.quote(code, safe=""),
                headers={"Accept": "text/html"},
            )
            response = connection.getresponse()
            response.read()
            cookies = [value for key, value in response.getheaders()
                       if key.lower() == "set-cookie"]
        finally:
            connection.close()
        if not cookies:
            raise RuntimeError("local_agent_pair_cookie_missing")
        return self.recent_session_url(), cookies[0]

    def pair_url(self) -> str:
        """Create a one-time browser pairing link for this server.

        OpenCode V2's web UI requires a pairing session cookie.  The CLI
        ``opencode pair`` talks to the background service, which is not this
        standalone server, so ask this exact server's /api/pair endpoint.
        """
        if not self.running or not self.port:
            raise RuntimeError("local_agent_not_running")
        value = self._request("POST", "/api/pair", timeout=5)
        code = str(value.get("code") or "")
        if not code:
            raise RuntimeError("local_agent_pair_failed")
        return (f"http://127.0.0.1:{self.port}/auth/connect/"
                f"{urllib.parse.quote(code, safe='')}")

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "port": self.port,
            "url": self.url if self.running else "",
        }

    def stop(self) -> None:
        with self._lock:
            process, self.process = self.process, None
            self.port = None
            self.url = ""
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
