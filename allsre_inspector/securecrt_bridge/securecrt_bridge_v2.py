# $language = "Python"
# $interface = "1.0"

"""ALLSRE SecureCRT tab agent, compatible with SecureCRT Python 2."""

import json
import os
import re
import time
import uuid

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Inspector installs this tab script below ``data/securecrt-bridge/client``.
# The embedded Bridge deliberately owns IPC below the parent runtime directory,
# not below ``client``.  Keep the source-tree fallback for standalone/manual
# use where this script is not installed in a directory named ``client``.
RUNTIME_DIR = (os.path.dirname(SCRIPT_DIR)
               if os.path.basename(SCRIPT_DIR).lower() == "client"
               else SCRIPT_DIR)
IPC_DIR = os.path.join(RUNTIME_DIR, "ipc-v2")
AGENT_KEYMAP = os.path.join(SCRIPT_DIR, "agent-input-lock.key")
SESSION_ID = "crt-" + uuid.uuid4().hex
POLL_SECONDS = 0.1
HEARTBEAT_SECONDS = 2
MAX_COMMAND_BYTES = 32768
MAX_RESULT_BYTES = 1024 * 1024
ORIGINAL_KEYMAP_NAME = ""
ORIGINAL_KEYMAP_FILE = ""
INPUT_LOCKED = False


def ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def write_json(path, payload):
    temporary = path + ".tmp-" + uuid.uuid4().hex
    handle = open(temporary, "wb")
    try:
        raw = json.dumps(payload, ensure_ascii=False)
        if not isinstance(raw, bytes):
            raw = raw.encode("utf-8")
        handle.write(raw)
    finally:
        handle.close()
    if os.path.exists(path):
        os.remove(path)
    os.rename(temporary, path)


def read_json(path):
    try:
        handle = open(path, "rb")
        try:
            return json.loads(handle.read().decode("utf-8"))
        finally:
            handle.close()
    except Exception:
        return None


def argument(name):
    prefix = name + "="
    try:
        for index in range(crt.Arguments.Count):
            value = crt.Arguments.GetArg(index)
            if value.startswith(prefix):
                return value[len(prefix):]
    except Exception:
        pass
    return ""


def option(name):
    try:
        return crt.GetScriptTab().Session.Config.GetOption(name) or ""
    except Exception:
        return ""


def escaped(value):
    return "".join(["\\%03o" % ord(char) for char in value])


def remaining(deadline):
    value = deadline - time.time()
    return 0 if value <= 0 else max(1, int(value + 0.999))


def response(request, success, output="", exit_code=None, code=None, message=None,
             started=None, truncated=False):
    request_id = request.get("requestId") or request.get("request_id") or ""
    return {
        "schemaVersion": 2, "requestId": request_id, "request_id": request_id,
        "sessionId": SESSION_ID, "session_id": SESSION_ID,
        "success": bool(success), "output": output,
        "exitCode": exit_code, "exit_code": exit_code,
        "errorCode": code, "errorMessage": message, "error": message,
        "startedAt": started or time.time(), "completedAt": time.time(),
        "truncated": bool(truncated),
    }


def clean_output(value):
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
    raw = value.encode("utf-8", "replace")
    truncated = len(raw) > MAX_RESULT_BYTES
    if truncated:
        value = raw[:MAX_RESULT_BYTES].decode("utf-8", "replace")
    return value.strip("\r\n"), truncated


def observed_prompt_mode():
    """Classify the visible prompt without sending a character to the host.

    This is intentionally conservative: it is used only to decide whether a
    Shell no-op may be attempted.  Anything interactive, streaming or
    unrecognised remains UNKNOWN and receives no automatic input.
    """
    try:
        row = int(screen.CurrentRow)
        columns = int(screen.Columns)
        rows = int(screen.Rows)
        start = max(1, row - 8)
        lines = []
        for line_row in range(start, min(rows, row) + 1):
            lines.append(screen.Get(line_row, 1, line_row, columns).rstrip())
    except Exception:
        return "UNKNOWN"
    line = ""
    for value in reversed(lines):
        if value.strip():
            line = value.strip()
            break
    if not line:
        return "UNKNOWN"
    upper = line.upper()
    if ("--MORE--" in upper or "(END)" in upper or "PASSWORD" in upper
            or "ARE YOU SURE" in upper):
        return "INTERACTIVE"
    # DM/disql, Oracle SQL*Plus, MySQL/MariaDB and PostgreSQL prompts.  Keep
    # this deliberately prompt-shaped; a random line ending in '>' is not SQL.
    if re.match(r"^(?:(?:DM\s+)?SQL|SQL\*PLUS|DMSQL|MYSQL|MARIADB(?:\s*\[[^\]]+\])?|"
                r"(?:[A-Za-z0-9_.-]+(?:db)?)?postgres)\s*(?:>|=>|=#)\s*$", line, re.I):
        return "SQL"
    # Standard POSIX prompts include [user@host dir]$ / #, user@host$, or
    # root#.  Do not accept a bare '$' because ordinary command output can end
    # in that character.
    if (re.search(r"(?:\]|[A-Za-z0-9_.@:/~ -])[#$]\s*$", line)
            or re.match(r"^[#$]\s*$", line)):
        return "SHELL"
    return "UNKNOWN"


def enable_agent_input_lock():
    """No-op: the SecureCRT window is shared by the operator and the Agent.

    Keeping the historical function (and its True return value) avoids a
    protocol change with older bridges, but it no longer swaps the keymap, so
    the operator can keep typing while the Agent is connected.
    """
    global INPUT_LOCKED
    INPUT_LOCKED = False
    return True


def _legacy_enable_agent_input_lock():
    global ORIGINAL_KEYMAP_NAME
    global ORIGINAL_KEYMAP_FILE
    global INPUT_LOCKED
    if INPUT_LOCKED:
        return True
    if not os.path.isfile(AGENT_KEYMAP):
        return False
    try:
        config = crt.GetScriptTab().Session.Config
        ORIGINAL_KEYMAP_NAME = config.GetOption("Keymap Name") or ""
        ORIGINAL_KEYMAP_FILE = config.GetOption("Keymap Filename V2") or ""
        # SecureCRT loads the selected keymap immediately when its name is
        # changed to Custom.  Set the file first: changing the name while the
        # filename is empty opens a modal "Unable to load keymap file" dialog
        # before this script can continue.
        config.SetOption("Keymap Filename V2", AGENT_KEYMAP)
        config.SetOption("Keymap Name", "Custom")
        INPUT_LOCKED = (
            (config.GetOption("Keymap Name") or "") == "Custom"
            and (config.GetOption("Keymap Filename V2") or "") == AGENT_KEYMAP
        )
        if INPUT_LOCKED:
            # Keep remote output in SecureCRT's synchronous script buffer.
            # The operator sees no terminal output, while ReadString() below
            # can still consume it and return it to the Agent.
            screen.Synchronous = True
        return INPUT_LOCKED
    except Exception:
        INPUT_LOCKED = False
        return False


def restore_input_mode():
    global INPUT_LOCKED
    if not INPUT_LOCKED:
        return
    try:
        config = crt.GetScriptTab().Session.Config
        # Never restore a stale lock-map path left by an older Inspector
        # checkout. SecureCRT shows a modal warning for a missing keymap while
        # opening the next session, which blocks unattended inspection.
        if ORIGINAL_KEYMAP_FILE and os.path.isfile(ORIGINAL_KEYMAP_FILE):
            config.SetOption("Keymap Name", ORIGINAL_KEYMAP_NAME or "Custom")
            config.SetOption("Keymap Filename V2", ORIGINAL_KEYMAP_FILE)
        else:
            # An empty filename means SecureCRT uses its built-in Default map;
            # it is preferable to a non-existent custom map.
            config.SetOption("Keymap Name", "Default")
            config.SetOption("Keymap Filename V2", "")
    except Exception:
        pass
    INPUT_LOCKED = False
    try:
        screen.Synchronous = False
    except Exception:
        pass


def handshake(request, timeout):
    started = time.time()
    challenge = str(request.get("challenge") or "").lower()
    if not re.match(r"^[a-f0-9]{16,64}$", challenge):
        return response(request, False, code="HANDSHAKE_CHALLENGE_INVALID",
                        message="invalid challenge", started=started)
    marker = "__ALLSRE_AGENT_TERMINAL_V1_" + challenge + "__"
    try:
        # Synchronous mode is enabled only while the bridge owns the screen.
        # Leaving it enabled in an idle HUMAN tab prevents normal interactive
        # input/output because nobody consumes the synchronous screen buffer.
        screen.Synchronous = True
        screen.Send("printf '%s'\r" % escaped("\n" + marker + "\n"))
        observed = screen.ReadString(marker, timeout)
    except Exception as error:
        return response(request, False, code="HANDSHAKE_READ_ERROR",
                        message=str(error), started=started)
    finally:
        try:
            # HUMAN terminals stay interactive. Agent terminals remain hidden:
            # their output is consumed only by the bridge command parser.
            screen.Synchronous = True if INPUT_LOCKED else False
        except Exception:
            pass
    if not observed:
        return response(request, False, code="HANDSHAKE_MARKER_TIMEOUT",
                        message="marker not observed", started=started)
    locked = enable_agent_input_lock()
    value = response(request, locked, exit_code=0 if locked else None,
                     code=None if locked else "AGENT_INPUT_LOCK_FAILED",
                     message=None if locked else "failed to disable operator keyboard input",
                     started=started)
    value["inputLocked"] = locked
    return value


def execute(request, timeout):
    started = time.time()
    command = request.get("command") or ""
    if not command or "\x00" in command:
        return response(request, False, code="COMMAND_INVALID",
                        message="empty command or NUL", started=started)
    if len(command.encode("utf-8", "replace")) > MAX_COMMAND_BYTES:
        return response(request, False, code="COMMAND_TOO_LARGE",
                        message="command exceeds 32 KB", started=started)
    token = uuid.uuid4().hex
    begin = "__ALLSRE_BEGIN_" + token + "__"
    end = "__ALLSRE_END_" + token + "__"
    # A systemctl/journalctl/git command sent to a real TTY may launch a
    # pager.  The pager never reaches the end marker, so the bridge would time
    # out and discard otherwise valid output.  Disable pagers for this one
    # bridged shell invocation.
    wrapped = (
        "export SYSTEMD_PAGER=cat PAGER=cat GIT_PAGER=cat; "
        "printf '%s'; %s; __allsre_rc=$?; printf '%s%%s\\n' \"$__allsre_rc\""
    ) % (escaped("\n" + begin + "\n"), command, escaped("\n" + end + ":"))
    deadline = time.time() + timeout
    try:
        screen.Synchronous = True
        screen.Send(wrapped + "\r")
        if not screen.ReadString(begin, remaining(deadline)):
            return response(request, False, code="BEGIN_MARKER_TIMEOUT",
                            message="begin marker timeout", started=started)
        output = screen.ReadString(end + ":", remaining(deadline))
        if output == "":
            return response(request, False, code="END_MARKER_TIMEOUT",
                            message="end marker timeout", started=started)
        raw_code = screen.ReadString("\n", remaining(deadline)).strip()
    except Exception as error:
        return response(request, False, code="SCREEN_READ_ERROR",
                        message=str(error), started=started)
    finally:
        try:
            # Agent output remains in the script buffer and is invisible to
            # the operator. HUMAN sessions never enter execute().
            screen.Synchronous = True if INPUT_LOCKED else False
        except Exception:
            pass
    output, truncated = clean_output(output)
    if not raw_code.isdigit():
        return response(request, False, output, code="EXIT_CODE_INVALID",
                        message="invalid exit code", started=started, truncated=truncated)
    exit_code = int(raw_code)
    return response(request, exit_code == 0, output, exit_code,
                    None if exit_code == 0 else "COMMAND_EXIT_NONZERO",
                    None if exit_code == 0 else "command exited with status %s" % exit_code,
                    started, truncated)


def execute_sql(request, timeout):
    """Send interactive database input verbatim and capture the next prompt.

    SQL clients do not understand the POSIX ``printf`` markers used by the
    shell protocol.  This raw-input path can therefore enter a database
    client from a shell, run SQL, and exit back to a shell.  It accepts both
    database and common Linux shell prompts because one terminal may change
    mode during a conversation.
    """
    started = time.time()
    command = request.get("command") or ""
    if not command or "\x00" in command:
        return response(request, False, code="COMMAND_INVALID", message="empty command or NUL", started=started)
    prompts = ["SQL> ", "SQL>", "# ", "$ "]
    deadline = time.time() + timeout
    try:
        screen.Synchronous = True
        screen.Send(command.rstrip("\r\n") + "\r")
        output = screen.ReadString(prompts, remaining(deadline))
    except Exception as error:
        return response(request, False, code="SQL_READ_ERROR", message=str(error), started=started)
    finally:
        try:
            screen.Synchronous = True if INPUT_LOCKED else False
        except Exception:
            pass
    if output == "":
        return response(request, False, code="INTERACTIVE_PROMPT_TIMEOUT",
                        message="SQL or shell prompt not observed", started=started)
    output, truncated = clean_output(output)
    return response(request, True, output, 0, started=started, truncated=truncated)


def execute_auto(request, timeout):
    """Route one input by the prompt currently visible in this exact tab."""
    mode = observed_prompt_mode()
    if mode == "SHELL":
        return execute(request, timeout)
    if mode == "SQL":
        return execute_sql(request, timeout)
    return response(request, False, code="TERMINAL_PROMPT_UNRECOGNIZED",
                    message="visible prompt is %s; no input was sent" % mode)


def shell_keepalive(request, timeout):
    """Run a Shell no-op only after an immediate passive prompt check."""
    started = time.time()
    if observed_prompt_mode() != "SHELL":
        return response(request, False, code="SHELL_PROMPT_NOT_OBSERVED",
                        message="terminal is not visibly at a Shell prompt", started=started)
    keepalive_request = dict(request)
    keepalive_request["command"] = ":"
    keepalive_request["terminalMode"] = "SHELL"
    return execute(keepalive_request, timeout)


def recover_prompt(request, timeout):
    """Interrupt an unobserved command and wait for a usable Shell/SQL prompt."""
    started = time.time()
    prompts = ["SQL> ", "SQL>", "=> ", "=# ", "# ", "$ "]
    try:
        screen.Synchronous = True
        screen.Send("\003")
        output = screen.ReadString(prompts, remaining(time.time() + timeout))
    except Exception as error:
        return response(request, False, code="PROMPT_RECOVERY_READ_ERROR",
                        message=str(error), started=started)
    finally:
        try:
            screen.Synchronous = True if INPUT_LOCKED else False
        except Exception:
            pass
    if output == "":
        return response(request, False, code="PROMPT_RECOVERY_TIMEOUT",
                        message="Ctrl+C did not yield an interactive prompt", started=started)
    output, truncated = clean_output(output)
    return response(request, True, output, exit_code=0, started=started, truncated=truncated)


def heartbeat(address, username, port, connected_at, screen_state):
    now = time.time()
    try:
        connected = bool(crt.GetScriptTab().Session.Connected)
    except Exception:
        connected = True
    return {
        "schemaVersion": 2, "sessionId": SESSION_ID, "session_id": SESSION_ID,
        "address": address, "username": username, "port": port,
        "connected": connected, "screenState": screen_state,
        "observedPromptMode": observed_prompt_mode(),
        "inputLocked": INPUT_LOCKED,
        "connectedAt": connected_at, "connected_at": connected_at,
        "lastSeenAt": now, "last_seen": now,
    }


def main():
    global screen
    try:
        screen = crt.GetScriptTab().Screen
        # Default to interactive mode. The script merely publishes heartbeat
        # while idle, so HUMAN sessions remain fully usable by their operator.
        screen.Synchronous = False
        try:
            screen.IgnoreEscape = True
        except Exception:
            pass
    except Exception as error:
        crt.Dialog.MessageBox("ALLSRE bridge init failed: " + str(error))
        return

    address = argument("bridge_host") or option("Hostname")
    username = argument("bridge_username") or option("Username")
    try:
        port = int(option("Port") or 22)
    except Exception:
        port = 22
    sessions_dir = os.path.join(IPC_DIR, "sessions")
    requests_dir = os.path.join(IPC_DIR, "requests", SESSION_ID)
    results_dir = os.path.join(IPC_DIR, "results")
    for path in (sessions_dir, requests_dir, results_dir):
        ensure_dir(path)
    heartbeat_path = os.path.join(sessions_dir, SESSION_ID + ".json")
    connected_at = time.time()
    next_heartbeat = 0
    failures = 0
    stopped = False
    screen_state = "SYNCHRONIZED"
    try:
        while not stopped:
            now = time.time()
            if now >= next_heartbeat:
                try:
                    write_json(heartbeat_path, heartbeat(address, username, port,
                                                         connected_at, screen_state))
                    failures = 0
                except Exception:
                    failures += 1
                    if failures >= 5:
                        break
                next_heartbeat = now + HEARTBEAT_SECONDS
            try:
                names = sorted(os.listdir(requests_dir))
            except Exception:
                names = []
            for name in names:
                if not name.endswith(".json"):
                    continue
                path = os.path.join(requests_dir, name)
                request = read_json(path)
                if not isinstance(request, dict):
                    continue
                if (request.get("sessionId") or request.get("session_id")) not in (None, "", SESSION_ID):
                    continue
                try:
                    os.remove(path)
                except Exception:
                    continue
                if float(request.get("expiresAt") or now + 1) < time.time():
                    result = response(request, False, code="REQUEST_EXPIRED", message="request expired")
                else:
                    try:
                        timeout = max(1, min(3600, int(request.get("timeoutSeconds") or request.get("timeout") or 30)))
                    except Exception:
                        timeout = 30
                    action = str(request.get("action") or "EXECUTE").upper()
                    if action == "HANDSHAKE":
                        result = handshake(request, min(timeout, 30))
                    elif action == "EXECUTE":
                        # rawInput is per-command: true sends the command
                        # verbatim (SQL/database prompt), false uses the Shell
                        # begin/end wrapper.  It does not label the terminal.
                        raw_input = request.get("rawInput")
                        terminal_mode = str(request.get("terminalMode") or "AUTO").upper()
                        if raw_input is None:
                            # Rolling-upgrade compatibility for callers that
                            # still send the retired terminal mode field.
                            if terminal_mode == "AUTO":
                                result = execute_auto(request, timeout)
                            elif terminal_mode == "SQL":
                                result = execute_sql(request, timeout)
                            else:
                                result = execute(request, timeout)
                        elif bool(raw_input):
                            result = execute_sql(request, timeout)
                        else:
                            result = execute(request, timeout)
                        # A missing marker only means this command did not
                        # yield a reliable result (it may still be running,
                        # paging, or be inside an interactive program).  It
                        # is not evidence that SecureCRT/SSH is disconnected.
                        # Keep the heartbeat session alive and let an operator
                        # decide how to recover the prompt.
                    elif action == "SHELL_KEEPALIVE":
                        result = shell_keepalive(request, min(timeout, 10))
                    elif action == "RECOVER_PROMPT":
                        result = recover_prompt(request, min(timeout, 10))
                    elif action == "FOCUS":
                        try:
                            # ``Window.Activate`` only raises SecureCRT as an
                            # application.  It does not necessarily select the
                            # tab that owns this bridge script, so an operator
                            # could be taken to the right window but still see
                            # a different server.  The script runs inside the
                            # target tab; explicitly select it first, then
                            # foreground the parent window.
                            script_tab = crt.GetScriptTab()
                            script_tab.Activate()
                            crt.Window.Activate()
                            result = response(request, True, exit_code=0)
                        except Exception as exc:
                            result = response(request, False, code="TERMINAL_FOCUS_FAILED", message=str(exc))
                    elif action == "STOP":
                        result = response(request, True, exit_code=0)
                        stopped = True
                    else:
                        result = response(request, False, code="UNSUPPORTED_ACTION", message="unsupported action")
                try:
                    write_json(os.path.join(results_dir, result["requestId"] + ".json"), result)
                except Exception:
                    pass
                if stopped:
                    break
            time.sleep(POLL_SECONDS)
    finally:
        restore_input_mode()
        try:
            if os.path.exists(heartbeat_path):
                os.remove(heartbeat_path)
        except Exception:
            pass


# Every window is shared by the operator and the Agent now; always register.
main()
