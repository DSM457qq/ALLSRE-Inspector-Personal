---
name: linux-host-inspection
description: 对当前 SecureCRT 终端登录的 Linux 主机执行只读巡检。
---

# Linux 主机巡检

## 规则

- 通过 `list_terminals` 确认目标 `terminalId`，一次只检查一台主机。
- 远端事实只能通过 `bash` 获取；当前是 SQL> 时不要用 bash。
- 只执行只读命令。不要写文件、安装软件、修改配置、重启服务或修改权限。
- 需要交付文件时，使用 `save_task_file` 保存到本机 `ALLSRE-files`，只传相对路径。
- 不使用分页器和持续输出；`systemctl`/`journalctl`/`git log` 加 `--no-pager`。
- 不确定的值输出 `unknown`，并在报告中说明。

## 流程

1. `list_terminals` 选择目标；
2. 按需求执行最小只读命令；
3. 汇总真实输出；
4. 如需报告，`save_task_file` 保存 Markdown；
5. 用中文给出简洁结论和证据。
