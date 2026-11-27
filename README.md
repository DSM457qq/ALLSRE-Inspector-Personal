# ALLSRE Inspector Personal

个人电脑使用的轻量 Inspector：

- SecureCRT 终端绑定；
- OpenCode V2 本地 Agent；
- `bash` / `sqlbash` / `list_terminals` / `save_task_file`；
- 本地只读分类和命令审批；
- 本地 SQLite 命令审计；
- 本地文件存储。

不包含：

- ConfigCenter / Worker 注册；
- 资产绑定、CAS、项目会话；
- 浏览器自动登录、VPN、堡垒机、Chrome、Playwright；
- 任务调度、Ansible、录制、受控变更。

## 安装

需要 Python 3.11+、Node.js 24+、OpenCode CLI 和 SecureCRT。

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
npm ci
Copy-Item .\inspector.personal.example.yaml .\inspector.yaml
```

编辑 `inspector.yaml` 中的模型配置。配置文件已被 `.gitignore` 忽略。

## 启动

```powershell
$env:ALLSRE_INSPECTOR_CONFIG = (Resolve-Path .\inspector.yaml)
allsre-inspector-personal
```

打开：

```text
http://127.0.0.1:8876/
```

或直接打开本地 Agent：

```text
http://127.0.0.1:8876/agent
```

## SecureCRT

Inspector 启动 SecureCRT Bridge 后，在 SecureCRT 中打开终端标签页，然后：

```text
GET /api/v1/tools/terminal-list
```

返回当前可用的 `terminalId`。OpenCode 插件会通过该列表选择终端。

## 从生产 Inspector 配置迁移

个人版只保留通用 OpenCode 和 SecureCRT 配置：

| 生产配置 | 个人版处理 |
|---|---|
| `opencode.executable` / `api_version` | 保留，固定使用 V2 |
| `opencode.agent` | 保留；值为 `opencode.json` 中存在的 agent 时才设为默认 |
| `opencode.startup_timeout` | 保留 |
| `opencode.model` / `model_config` | 保留 |
| `opencode.model_thinking` | 保留，默认 `false` |
| `opencode.pure` | 忽略；V2 不需要，配置隔离由 `OPENCODE_DISABLE_PROJECT_CONFIG` 完成 |
| `opencode.skill_load_timeout` | 忽略；个人版没有 Author/任务 skill 预加载 |
| `opencode.session_timeout` / `request_timeout` | 忽略；由 OpenCode 原生会话控制 |
| `agent_ui.tunnel.*` | 删除；没有 ConfigCenter 反向隧道 |
| `agent_ui.tools.command_policy` | 删除；个人版固定使用只读分类/审批 |
| `agent_ui.tools.allow_unbound_file_write` | 删除；`save_task_file` 始终写入本地受限目录 |
| `worker_id` / `worker_token` / `control_plane` | 删除 |
| `chrome` / `browser_agent` / `vpn_runtime` / `ansible_engine` | 删除 |

## 本地 API

```text
GET  /health
GET  /api/v1/tools/terminal-list
POST /api/v1/tools/bash/classify
POST /api/v1/tools/bash
POST /api/v1/tools/task-file
GET  /api/v1/terminals
POST /api/v1/terminals/{terminal_id}/focus
GET  /api/v1/local/audits
POST /api/v1/local-agent/start
GET  /api/v1/local-agent/status
POST /api/v1/local-agent/stop
```

所有服务只绑定 `127.0.0.1`。

## 测试

```powershell
python -m pytest -q
python -m compileall allsre_inspector
```
