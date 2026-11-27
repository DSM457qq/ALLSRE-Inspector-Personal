---
name: incident-troubleshooting
description: 通过逐步取证排查当前 SecureCRT 终端上的服务器、数据库、网络或应用故障。
---

# 故障排查

## 规则

- 先用 `list_terminals` 确认目标和 `terminalId`。
- Shell 用 `bash`，SQL> 用 `sqlbash`；不要猜测当前模式。
- 每次只做一个最小、只读的检查，根据真实输出决定下一步。
- 不执行变更；需要修复时给出步骤，由用户明确授权。
- 禁止分页器和持续输出；使用 `--no-pager`、`tail -n`、`top -b -n 1`。
- 区分已观察事实、推断和未验证假设。
- 不泄露凭据、Token 或敏感信息。

## 报告

给出故障现象、影响、证据、根因判断、建议步骤和验证方法。需要保存时使用 `save_task_file`。
