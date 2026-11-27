import { Plugin } from "@opencode/plugin";

type ToolContext = { sessionID: string; signal: AbortSignal };
type Input = Record<string, unknown>;

const baseUrl = () => (process.env.ALLSRE_INSPECTOR_API_BASE || "http://127.0.0.1:8876").replace(/\/+$/, "");

async function inspectorRequest(path: string, context: ToolContext, body?: unknown) {
  const headers: Record<string, string> = {
    "X-OpenCode-Session-ID": context.sessionID,
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(`${baseUrl()}${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: context.signal,
  });
  const text = await response.text();
  if (!response.ok) throw new Error(text || `Inspector request failed: HTTP ${response.status}`);
  return { content: text };
}

const string = (description?: string, extra: Input = {}) => ({ type: "string", ...(description ? { description } : {}), ...extra });
const integer = (description?: string, extra: Input = {}) => ({ type: "integer", ...(description ? { description } : {}), ...extra });
const object = (properties: Input, required: string[] = [], extra: Input = {}) => ({ type: "object", properties, required, additionalProperties: false, ...extra });

const terminalInput = object({
  command: string("要在当前 SecureCRT 终端执行的命令"),
  timeout: integer("等待结果的秒数，默认 30", { minimum: 1 }),
  terminalId: string("list_terminals 返回的 terminalId"),
}, ["command"]);

async function classifyBash(command: string, context: ToolContext): Promise<string | null> {
  try {
    const result = await inspectorRequest("/api/v1/tools/bash/classify", context, { command });
    const value = JSON.parse(result.content);
    const classification = String(value?.classification || "").toUpperCase();
    if (classification === "READ_ONLY" || classification === "DESTRUCTIVE") return classification;
  } catch {
    // Never auto-allow when the local classifier is unavailable.
  }
  return null;
}

export default Plugin.define({
  id: "allsre-personal-tools",
  async setup(ctx) {
    await ctx.tool.transform((editor) => {
      editor.add({
        name: "bash",
        description: "在 SecureCRT Shell 提示符下执行普通 Shell 命令。SQL> 时请使用 sqlbash。",
        input: terminalInput,
        options: { permission: "bash" },
        async execute(input, context) {
          const args = input as { command: string; timeout?: number; terminalId?: string };
          const classification = (await classifyBash(args.command, context)) || "MUTATING";
          const action = classification === "READ_ONLY" ? "bash_readonly"
            : classification === "DESTRUCTIVE" ? "bash_destructive" : "bash";
          await ctx.permission.assert({ sessionID: context.sessionID as any, action, resources: [args.command] });
          if (classification === "DESTRUCTIVE") throw new Error("destructive_command_denied");
          return inspectorRequest("/api/v1/tools/bash", context, {
            command: args.command,
            timeout: args.timeout || 30,
            terminalId: args.terminalId || null,
            rawInput: false,
            ...(classification !== "MUTATING" ? { classification } : {}),
          });
        },
      });
      editor.add({
        name: "sqlbash",
        description: "在 SQL>、mysql> 等数据库提示符下原样发送一条短 SQL。不要用于普通 Shell 命令，也不要启动/退出数据库客户端；不要用 GROUP_CONCAT/UNION ALL 拼接大量表。",
        input: terminalInput,
        options: { permission: "sqlbash" },
        async execute(input, context) {
          const args = input as { command: string; timeout?: number; terminalId?: string };
          const maxSqlChars = Number(process.env.ALLSRE_SQLBASH_MAX_CHARS || 2000);
          if (args.command.length > maxSqlChars) {
            throw new Error(
              `SQL_COMMAND_TOO_LONG: ${args.command.length} characters; ` +
              `limit ${maxSqlChars}. Split into one statement per call, ` +
              `query metadata first, then scan table by table.`,
            );
          }
          await ctx.permission.assert({ sessionID: context.sessionID as any, action: "sqlbash", resources: [args.command] });
          return inspectorRequest("/api/v1/tools/bash", context, {
            command: args.command,
            timeout: args.timeout || 30,
            terminalId: args.terminalId || null,
            rawInput: true,
          });
        },
      });
      editor.add({
        name: "list_terminals",
        description: "列出当前已打开的 SecureCRT 终端（terminalId、名称、IP）。",
        input: object({}),
        options: { permission: "list_terminals" },
        async execute(_input, context) {
          await ctx.permission.assert({ sessionID: context.sessionID as any, action: "list_terminals", resources: ["*"] });
          return inspectorRequest("/api/v1/tools/terminal-list", context);
        },
      });
      editor.add({
        name: "save_task_file",
        description: "将 Markdown、JSON、CSV 或报告保存到本机 ALLSRE-files 目录；path 必须是相对路径。",
        input: object({
          path: string("ALLSRE-files 下的相对路径", { minLength: 1, maxLength: 500 }),
          content: string("完整 UTF-8 文本内容", { maxLength: 4000000 }),
        }, ["path", "content"]),
        options: { permission: "save_task_file" },
        async execute(input, context) {
          const args = input as { path: string; content: string };
          await ctx.permission.assert({ sessionID: context.sessionID as any, action: "save_task_file", resources: [args.path] });
          return inspectorRequest("/api/v1/tools/task-file", context, args);
        },
      });
    });
  },
});
