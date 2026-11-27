from __future__ import annotations

from contextlib import asynccontextmanager
import asyncio
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from ..core.errors import ServiceError
from ..core.readonly_policy import classify_bash_command
from ..schemas.models import TaskFileWrite, ToolCommand
from ..securecrt_bridge import SecureCRTBridgeService
from ..services.file_service import FileStorageService
from .agent import LocalAgentRuntime
from .audit import PersonalAuditStore
from .config import PersonalSettings
from .terminal import PersonalTerminalService
from .terminal_directory import PersonalTerminalDirectory
from .tools import PersonalToolService


class PersonalState:
    def __init__(self, settings: PersonalSettings, project_root: Path) -> None:
        self.settings = settings
        self.project_root = project_root
        self.bridge = SecureCRTBridgeService(settings.securecrt, settings.data_dir)
        self.terminals = PersonalTerminalService(settings)
        self.terminal_directory = PersonalTerminalDirectory(settings, self.terminals)
        self.files = FileStorageService(settings.file_storage_dir)
        self.audit = PersonalAuditStore(settings.data_dir / "personal.sqlite3")
        self.tools = PersonalToolService(
            self.terminal_directory, self.files, self.audit,
            bash_classification_enabled=settings.bash_classification_enabled,
        )
        self.agent = LocalAgentRuntime(settings, project_root)

    def start(self) -> None:
        if self.settings.securecrt.get("enabled", True):
            try:
                self.bridge.start()
            except Exception:
                # The web UI must stay available so the operator can inspect
                # SecureCRT configuration; terminal tools report unavailable.
                pass
        self.terminal_directory.start_background(10.0)

    def stop(self) -> None:
        self.agent.stop()
        self.bridge.stop()

    def health(self) -> dict[str, Any]:
        bridge = self.bridge.diagnostics()
        return {
            "status": "ok" if bridge.get("available") or not bridge.get("enabled") else "degraded",
            "service": "allsre-inspector-personal",
            "bashClassificationEnabled": self.tools.bash_classification_enabled,
            "securecrtBridge": bridge,
            "terminals": self.terminals.health(),
            "agent": self.agent.status(),
        }


def _local_only(request: Request) -> None:
    host = str(request.client.host if request.client else "").lower()
    if host not in {"127.0.0.1", "::1", "localhost", "testclient"}:
        raise HTTPException(status_code=403, detail={"code": "LOOPBACK_ONLY"})


def create_app(settings: PersonalSettings) -> FastAPI:
    project_root = Path(__file__).resolve().parents[2]
    state = PersonalState(settings, project_root)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        state.start()
        try:
            yield
        finally:
            state.stop()

    app = FastAPI(title="ALLSRE Inspector Personal", version="0.1.0", lifespan=lifespan)
    app.state.personal = state
    static = project_root / "static" / "index.html"

    @app.get("/health")
    def health() -> dict[str, Any]:
        return state.health()

    @app.get("/api/v1/tools/terminal-list")
    def terminal_list(request: Request, _: None = Depends(_local_only)) -> dict[str, Any]:
        return {"items": state.terminal_directory.list_terminals()}

    @app.post("/api/v1/tools/bash/classify")
    def classify_bash(body: dict[str, Any], request: Request,
                      _: None = Depends(_local_only)) -> dict[str, Any]:
        if not state.tools.bash_classification_enabled:
            return {
                "classification": "READ_ONLY",
                "reason": "classification_disabled",
                "policyVersion": "disabled",
                "segments": 1,
            }
        return classify_bash_command(str(body.get("command") or ""))

    @app.post("/api/v1/tools/bash")
    def bash(body: ToolCommand, request: Request,
             _: None = Depends(_local_only)) -> dict[str, Any]:
        try:
            return state.tools.execute(body)
        except ServiceError as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.post("/api/v1/tools/task-file")
    def task_file(body: TaskFileWrite, request: Request,
                  _: None = Depends(_local_only)) -> dict[str, Any]:
        try:
            return state.tools.save_file(body)
        except ServiceError as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.get("/api/v1/terminals")
    def terminals(request: Request, _: None = Depends(_local_only)) -> dict[str, Any]:
        return {"items": state.terminal_directory.list_terminals()}

    @app.post("/api/v1/terminals/{terminal_id}/focus")
    def focus(terminal_id: str, request: Request,
              _: None = Depends(_local_only)) -> dict[str, Any]:
        try:
            return state.terminal_directory.focus_terminal(terminal_id)
        except Exception as exc:
            raise HTTPException(status_code=404, detail={"code": str(exc) or "TERMINAL_NOT_FOUND"}) from exc

    @app.get("/api/v1/local/audits")
    def audits(limit: int = 100, request: Request = None,
               _: None = Depends(_local_only)) -> dict[str, Any]:
        return state.tools.audits(limit)

    @app.post("/api/v1/local-agent/start")
    async def start_agent(request: Request, _: None = Depends(_local_only)) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(state.agent.start)
        except Exception as exc:
            raise HTTPException(status_code=503, detail={
                "code": "LOCAL_AGENT_START_FAILED", "message": str(exc)[:300],
            }) from exc

    @app.get("/api/v1/local-agent/status")
    def agent_status(request: Request, _: None = Depends(_local_only)) -> dict[str, Any]:
        return state.agent.status()

    @app.post("/api/v1/local-agent/stop")
    def stop_agent(request: Request, _: None = Depends(_local_only)) -> dict[str, Any]:
        state.agent.stop()
        return {"ok": True}

    @app.get("/agent")
    def open_agent(request: Request, _: None = Depends(_local_only)):
        try:
            if not state.agent.running:
                state.agent.start()
            target, cookie = state.agent.pair_cookie()
        except Exception as exc:
            raise HTTPException(status_code=503, detail={
                "code": "LOCAL_AGENT_PAIR_FAILED", "message": str(exc)[:300],
            }) from exc
        # Redeem the one-time code on the Inspector side and forward its
        # OpenCode session cookie.  Cookies are host-scoped, not port-scoped,
        # so the browser can then authenticate to the OpenCode server and land
        # directly on the newest session instead of its history page.
        return RedirectResponse(target, status_code=307, headers={
            "set-cookie": cookie,
            "cache-control": "no-store",
        })

    @app.get("/")
    def home():
        if static.is_file():
            return FileResponse(static)
        return JSONResponse({"service": "allsre-inspector-personal", "agent": "/agent"})

    return app
