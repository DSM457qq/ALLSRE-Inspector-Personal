# ALLSRE Inspector Personal 部署文档

本文档面向人工运维和自动化 AI Agent，目标是从零部署一套“个人电脑 + SecureCRT + 本地 OpenCode”的 Inspector。

## 1. 部署边界

### 包含

- 本机 SecureCRT 终端发现、绑定、聚焦；
- 本地 OpenCode V2 Agent；
- `bash`、`sqlbash`、`list_terminals`、`save_task_file`；
- 只读分类、审批、命令审计；
- 本地文件存储；
- 本机回环访问。

### 不包含

- ConfigCenter / Worker 注册和心跳；
- 资产绑定、CAS、项目会话；
- 浏览器自动登录、Chrome、Playwright；
- VPN、堡垒机、Ansible、录制、受控变更；
- SFTP。

## 2. 目标拓扑

```text
SecureCRT 标签页
        │  2s 标签页心跳 + 可选 Shell 保活
        ▼
SecureCRT Bridge  127.0.0.1:8765
        ▲
        │
Inspector Personal  127.0.0.1:8876
        │
        ├─ /                   本机控制台
        ├─ /health             健康检查
        ├─ /api/v1/tools/*     工具 API
        └─ /agent              配对并打开最近会话
                │
                ▼
        OpenCode V2  127.0.0.1:<动态端口>
                │
                └─ .opencode/plugins/allsre-tools
```

所有监听地址必须是回环地址，禁止绑定 `0.0.0.0`。

## 3. 前置条件

| 组件 | 要求 |
|---|---|
| 操作系统 | Windows 10/11 x64；SecureCRT Bridge 依赖 Windows SecureCRT |
| Python | 3.11 或更高 |
| Node.js | 22 LTS 或 24，需包含 npm |
| Git | 任意近期版本 |
| SecureCRT | 已能正常打开目标 SSH/数据库会话 |
| OpenCode | 2.x；仓库固定依赖 `@opencode/cli 2.3.2` |
| 网络 | 能访问模型 `baseUrl`；不需要 ConfigCenter |

检查命令：

```powershell
python --version
node --version
npm --version
git --version
```

如果 `opencode` 不在 PATH：

```powershell
cd <安装目录>
npm ci
.\\node_modules\\.bin\\opencode.cmd --version
```

Inspector 会自动查找项目内的 `node_modules/.bin/opencode.cmd`，也可以在配置中写绝对路径。

## 4. 安装

### 4.1 目录约定

以下示例使用：

```text
C:\ALLSRE\ALLSRE-Inspector-Personal
```

实际路径可以不同，但后续命令必须整体替换。

### 4.2 克隆和依赖

```powershell
New-Item -ItemType Directory -Force C:\ALLSRE | Out-Null
cd C:\ALLSRE
git clone https://github.com/DSM457qq/ALLSRE-Inspector-Personal.git
cd .\ALLSRE-Inspector-Personal

python -m venv .venv
.\\.venv\\Scripts\\python.exe -m pip install --upgrade pip
.\\.venv\\Scripts\\python.exe -m pip install -e ".[dev]"

npm ci
```

如果只需要运行、不跑测试，可以安装：

```powershell
.\\.venv\\Scripts\\python.exe -m pip install -e .
```

### 4.3 安装校验

```powershell
.\\.venv\\Scripts\\python.exe -c "import fastapi, uvicorn, yaml; print('python deps ok')"
.\\node_modules\\.bin\\opencode.cmd --version
```

## 5. 配置

### 5.1 创建配置文件

```powershell
Copy-Item .\\inspector.personal.example.yaml .\\inspector.yaml
```

`inspector.yaml` 已被 `.gitignore` 忽略，禁止提交到 Git。

### 5.2 最小配置

```yaml
listen_host: 127.0.0.1
listen_port: 8876
data_dir: data
# Optional; defaults to Desktop\ALLSRE-files

securecrt_bridge:
  enabled: true
  host: 127.0.0.1
  port: 8765
  shell_keepalive_enabled: true
  shell_keepalive_interval_seconds: 90

opencode:
  executable: auto
  api_version: "2"
  agent: inspector
  startup_timeout: 30
  model_thinking: false
  model: custom/your-model
  model_config:
    providerId: custom
    modelId: your-model
    baseUrl: "https://model.example/v1"
    apiKey: "REPLACE_ME"
```

### 5.3 字段说明

| 字段 | 说明 |
|---|---|
| `listen_host` | 只能是 `127.0.0.1`、`localhost` 或 `::1` |
| `listen_port` | Inspector HTTP 端口，默认 8876 |
| `data_dir` | 审计库、OpenCode 运行时配置、Bridge 数据 |
| `file_storage_dir` | `save_task_file` 的根目录；默认桌面 `ALLSRE-files` |
| `securecrt_bridge.enabled` | 是否启动本机 Bridge |
| `securecrt_bridge.port` | Bridge 端口，默认 8765 |
| `shell_keepalive_enabled` | 空闲 Shell 保活；示例默认开启 |
| `shell_keepalive_interval_seconds` | 保活间隔，代码下限 30 秒 |
| `opencode.executable` | `auto` 或 OpenCode 绝对路径 |
| `opencode.api_version` | 必须为 `"2"` |
| `opencode.agent` | 必须是 `opencode.json` 中存在的 agent |
| `opencode.model` | `providerId/modelId` |
| `opencode.model_config` | OpenAI-compatible 端点配置 |
| `opencode.model_thinking` | 是否启用模型 thinking |

### 5.3.1 文件保存路径

默认保存到当前用户桌面：

```text
C:\Users\<用户名>\Desktop\ALLSRE-files
```

如果桌面被 OneDrive 或组策略重定向，Inspector 使用 Windows 的桌面已知目录
（`SHGetFolderPathW(CSIDL_DESKTOPDIRECTORY)`），因此会跟随实际桌面位置。

如需自定义：

```yaml
file_storage_dir: D:\ALLSRE\files
```

Inspector 启动时会创建该目录；`save_task_file` 只允许写入该根目录以下的相对路径。

### 5.4 模型配置注意事项

1. `providerId` 可以包含中文，但必须与 `opencode.model` 前缀一致。
2. `modelId` 必须是模型服务实际接受的名称。
3. `baseUrl` 通常以 `/v1` 结尾；不要重复拼接 `/v1`。
4. `apiKey` 只保存在本机 `inspector.yaml`，不写入仓库。
5. 若模型不支持 thinking，保持 `model_thinking: false`。
6. 修改配置后必须重启 Inspector。

## 6. 启动和停止

### 6.1 启动

```powershell
cd C:\ALLSRE\ALLSRE-Inspector-Personal
.\\scripts\\start-personal.ps1
```

脚本会：

- 检查 `.venv` 和 `inspector.yaml`；
- 后台启动 `allsre_inspector.personal.main`；
- 等待健康检查；
- 输出 Inspector PID。

也可以前台运行，便于查看日志：

```powershell
.\\.venv\\Scripts\\python.exe -m allsre_inspector.personal.main --config .\\inspector.yaml
```

### 6.2 停止

```powershell
.\\scripts\\stop-personal.ps1
```

手动停止时，先找监听进程：

```powershell
Get-NetTCPConnection -State Listen -LocalPort 8876,8765 |
  Select-Object LocalPort,OwningProcess
```

只终止属于本仓库 `.venv` 的 Python 进程，不要按进程名批量终止其他 Python 服务。

### 6.3 验证健康

```powershell
curl.exe -sS http://127.0.0.1:8876/health
```

正常结果包含：

```json
{
  "status": "ok",
  "service": "allsre-inspector-personal",
  "securecrtBridge": {"available": true},
  "agent": {"running": false}
}
```

Agent 未打开时 `agent.running=false` 是正常的。

## 7. SecureCRT 配置

### 7.1 建立终端

1. 启动 Inspector；
2. 在 SecureCRT 中打开目标会话标签页；
3. 确认标签页处于可用状态；
4. 访问：

```text
http://127.0.0.1:8876/api/v1/tools/terminal-list
```

正常返回：

```json
{
  "items": [
    {
      "terminalId": "crt-...",
      "name": "host-a",
      "ip": "10.0.0.10",
      "address": "10.0.0.10:22",
      "kind": "securecrt"
    }
  ]
}
```

### 7.2 两层保活

| 机制 | 默认 | 作用 |
|---|---|---|
| 标签页注册心跳 | 始终开启，每 2 秒 | 让 Inspector 发现 SecureCRT 标签页 |
| Shell 空闲保活 | 默认关闭；示例开启 90 秒 | 防止 SSH/堡垒机因无输入断开 |

### 7.3 没有终端时检查

```powershell
curl.exe -sS http://127.0.0.1:8876/health
```

检查：

- `securecrtBridge.available` 是否为 `true`；
- `securecrtBridge.port` 是否与配置一致；
- 8765 是否被占用；
- `data\securecrt-bridge\bridge.token` 是否存在；
- SecureCRT 标签页是否加载了 Bridge 脚本；
- 是否打开了 SecureCRT 标签页后再刷新列表。

如果本机同时运行生产 Inspector，两者不能同时占用同一个 Bridge 端口。个人版可改成：

```yaml
securecrt_bridge:
  port: 8766
```

然后重启 Personal Inspector。

## 8. 打开 Agent

必须访问：

```text
http://127.0.0.1:8876/agent
```

不要直接打开 OpenCode 动态端口，否则会看到“连接到服务器 / 配对链接”页面。

`/agent` 的流程：

1. 启动或复用本地 OpenCode；
2. Inspector 服务端调用该 OpenCode 的 `/api/pair`；
3. 服务端兑换一次性配对码；
4. 将 OpenCode 会话 Cookie 转发给浏览器；
5. 查询 `ses_*` 会话；
6. 跳转到最近更新的会话。

配对 Cookie 是临时的；重新打开 `/agent` 会重新生成。

## 9. 验收清单

### 9.1 基础

```powershell
curl.exe -sS http://127.0.0.1:8876/health
curl.exe -sS http://127.0.0.1:8876/
curl.exe -sS http://127.0.0.1:8876/api/v1/tools/terminal-list
```

预期：

- `/health` 返回 200，`service` 正确；
- `/` 返回本地控制台 HTML；
- 终端列表返回至少一个 SecureCRT 终端。

### 9.2 Agent

用浏览器访问：

```text
http://127.0.0.1:8876/agent
```

预期：

- 不再出现裸 OpenCode 端口；
- 自动进入 OpenCode UI；
- 自动打开最近会话；
- 模型选择器只显示配置的 provider/model；
- 不出现免费模型目录。

### 9.3 工具

在 Agent 中依次验证：

```text
list_terminals
bash: uname -a
sqlbash: select 1 from dual   （仅在 SQL> 提示符下）
save_task_file: reports/check.md
```

预期：

- `bash` 能通过 SecureCRT 标签页执行；
- SQL 提示符下使用 `sqlbash`；
- 文件写入 `file_storage_dir`，路径越界被拒绝；
- 审计表有记录：

```text
GET /api/v1/local/audits
```

### 9.4 测试

```powershell
.\\.venv\\Scripts\\python.exe -m pytest -q
.\\.venv\\Scripts\\python.exe -m compileall -q allsre_inspector
```

仓库当前的预期结果是 `125 passed`。

## 10. 日志和数据

| 路径 | 内容 |
|---|---|
| `data\personal.sqlite3` | 命令审计 |
| `data\opencode-personal.runtime.json` | 生成的 OpenCode 配置 |
| `data\opencode-personal.log` | OpenCode 日志 |
| `data\securecrt-bridge\` | Bridge token、IPC、客户端脚本 |
| `data\files\` | `save_task_file` 文件 |

查看进程和端口：

```powershell
Get-NetTCPConnection -State Listen -LocalPort 8765,8876 |
  Select-Object LocalAddress,LocalPort,OwningProcess
```

## 11. 安全要求

1. `listen_host` 必须是回环地址，禁止 `0.0.0.0`。
2. 不要将 8876 或 8765 暴露到局域网或公网。
3. `inspector.yaml` 含模型 API Key，必须限制文件权限。
4. 不要把 `inspector.yaml`、`data/` 提交到 Git。
5. 不要复用生产 Worker Token。
6. 保持只读分类和 destructive 拒绝策略；个人版没有 `unrestricted` 开关。
7. `save_task_file` 只允许写入配置的本地目录。

## 12. 升级

```powershell
cd C:\ALLSRE\ALLSRE-Inspector-Personal
.\\scripts\\stop-personal.ps1

Copy-Item .\\inspector.yaml .\\inspector.yaml.bak
Copy-Item .\\data .\\data.bak -Recurse

git pull --ff-only
.\\.venv\\Scripts\\python.exe -m pip install -e ".[dev]"
npm ci
.\\scripts\\start-personal.ps1
```

升级后执行第 9 节验收清单。

## 13. 回滚

```powershell
.\\scripts\\stop-personal.ps1
git log --oneline -5
git checkout <上一个稳定提交>
.\\.venv\\Scripts\\python.exe -m pip install -e .
.\\scripts\\start-personal.ps1
```

回滚前备份 `data/`。不要直接删除审计库。

## 14. 常见问题

### 8876 端口被占用

```powershell
Get-NetTCPConnection -State Listen -LocalPort 8876 |
  Select-Object LocalPort,OwningProcess
Get-Process -Id <PID> | Select-Object Id,ProcessName,Path
```

确认是本仓库的 Personal Inspector 后再停止。

### 8765 被生产 Inspector 占用

修改：

```yaml
securecrt_bridge:
  port: 8766
```

重启 Personal。生产版和个人版不能同时使用同一个 Bridge 端口。

### OpenCode 未找到

```powershell
Get-Command opencode -ErrorAction SilentlyContinue
dir .\\node_modules\\.bin\\opencode*
```

配置绝对路径：

```yaml
opencode:
  executable: C:\ALLSRE\ALLSRE-Inspector-Personal\node_modules\.bin\opencode.cmd
```

### 打开 Agent 显示“连接到服务器”

错误访问了 OpenCode 动态端口。改用：

```text
http://127.0.0.1:8876/agent
```

### Agent 显示 Unrecognised route

确认代码已经包含 `/server/<base64(server-origin)>/session/<id>` 路由；旧版本曾错误使用目录编码。

### Agent 模型列表仍有免费模型

1. 确认 Inspector 已重启；
2. 检查 `data/opencode-personal.runtime.json`：
   - 有 `providers` 且只有配置的 provider；
   - 有 `policies`，第一条为 deny，第二条 allow；
3. 确认 `OPENCODE_DISABLE_FREE_MODELS=1`；
4. 清除浏览器缓存后重新打开 `/agent`。

### 模型 401 / 400

检查：

- `baseUrl` 是否可访问；
- `apiKey` 是否有效；
- `modelId` 是否与服务端一致；
- 是否需要 `/v1`；
- `providerId/modelId` 是否与配置一致。

### SecureCRT 列表为空

按第 7.3 节检查 Bridge、端口、标签页脚本和 SecureCRT 会话状态。

## 15. AI 部署执行顺序

自动部署 Agent 应按以下顺序执行，并在每步失败时停止：

```text
1. 检查 Windows / Python >=3.11 / Node / Git / SecureCRT
2. git clone 或 git pull --ff-only
3. 创建 .venv
4. pip install -e ".[dev]"
5. npm ci
6. 若 inspector.yaml 不存在，复制示例
7. 校验 listen_host 为回环地址
8. 启动 Inspector
9. GET /health 必须 200
10. 打开 SecureCRT 标签页
11. GET /api/v1/tools/terminal-list 至少一项
12. 浏览器访问 /agent，确认进入最近会话
13. 执行 bash uname -a
14. 执行 save_task_file 测试
15. 检查 /api/v1/local/audits
```

禁止自动执行：

- 将 `listen_host` 改为 `0.0.0.0`；
- 把 8876/8765 暴露到公网；
- 覆盖已有 `inspector.yaml`；
- 删除 `data/`；
- 使用生产 Worker Token；
- 把 API Key 写入 Git。

## 16. 与生产 Inspector 共存

| 项目 | 个人版 | 生产版 |
|---|---|---|
| 用途 | 本机 SecureCRT | ConfigCenter Worker |
| HTTP 端口 | 8876 | 通常 8876，可改 |
| Bridge 端口 | 8765 或 8766 | 8765 |
| 数据目录 | `data/` | Worker 数据目录 |
| ConfigCenter | 无 | 有 |
| 浏览器自动化 | 无 | 有 |

共存要求：

1. 使用不同安装目录和不同 `.venv`；
2. 使用不同 HTTP 端口；
3. **不能同时使用同一个 SecureCRT Bridge 端口**；
4. 不要共享 `data/`；
5. 不要在两个实例之间复制 token。
