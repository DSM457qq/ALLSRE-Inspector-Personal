"""Read-only policy for interactive Agent bash commands.

This policy is intentionally separate from the controlled-change read-only
guard.  It answers one question: may this exact command be auto-allowed in the
interactive Agent, or must it go through the human approval action?
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import bashlex

from .security import destructive_command_reason

READ_ONLY = "READ_ONLY"
MUTATING = "MUTATING"
DESTRUCTIVE = "DESTRUCTIVE"
POLICY_VERSION = "readonly-v4"
MAX_COMMAND_CHARS = 16_000

_INTERPRETERS = {
    "bash", "sh", "zsh", "dash", "ksh", "ash", "eval", "exec", "source", ".",
    "xargs", "sudo", "su", "python", "python3", "perl", "ruby", "node",
}
_READ_ONLY_COMMANDS = {
    "awk", "basename", "cal", "cat", "cksum", "cut", "date", "df", "dirname", "dmesg",
    "du", "echo", "egrep", "false", "fgrep", "file", "find", "findmnt", "free",
    "getenforce", "getent", "grep", "groups", "head", "host", "hostname",
    "hostnamectl", "id", "dig", "dmidecode", "nslookup", "ping", "traceroute",
    "sestatus", "pidstat", "systemd-cgls", "systemd-cgtop",
    "iptables", "ip6tables", "nft", "firewall-cmd",
    "iostat", "ip", "journalctl", "last", "lastb", "localectl", "loginctl",
    "ls", "lsblk", "lscpu", "lsmod", "lsof", "lspci", "lsusb", "lsns",
    "md5sum", "mpstat", "netstat", "nproc", "nstat", "pgrep", "pidof",
    "printenv", "printf", "ps", "pstree", "pwd", "readlink", "realpath", "sar",
    "sha1sum", "sha256sum", "sha512sum", "sort", "ss", "stat", "systemctl",
    "systemd-analyze", "tail", "test", "timedatectl", "top", "tr", "true",
    "uname", "uniq", "uptime", "users", "vmstat", "w", "wc", "which", "who",
    "sleep", "git", "docker", "kubectl", "rpm", "dpkg", "apt", "apt-get",
    "yum", "dnf", "command",
}
_SYSTEMCTL_READ_ONLY = {
    "status", "show", "is-active", "is-enabled", "is-failed", "is-system-running",
    "list-units", "list-unit-files", "list-sockets", "list-timers",
    "list-dependencies", "help",
}
_DOCKER_READ_ONLY = {
    "version", "info", "ps", "images", "inspect", "stats", "logs", "top",
    "port", "events", "diff", "history",
}
_KUBECTL_READ_ONLY = {
    "version", "get", "describe", "logs", "top", "explain", "api-resources",
    "api-versions", "cluster-info", "auth",
}
_JOURNAL_MUTATING_OPTIONS = {
    "--vacuum-size", "--vacuum-time", "--vacuum-files", "--rotate", "--flush",
    "--setup-keys", "--relinquish-var", "--sync", "-f", "--follow",
}
_TAIL_FOLLOW_OPTIONS = {"-f", "-F", "--follow", "--retry"}
_IP_MUTATING = {"add", "del", "delete", "flush", "replace", "change", "set"}
_FIND_MUTATING = {
    "-delete", "-exec", "-execdir", "-ok", "-okdir",
    "-fprint", "-fprint0", "-fprintf", "-fls",
}
_HOSTNAME_MUTATING_OPTIONS = {"-F", "--file", "-b", "--boot"}
_SORT_MUTATING_OPTIONS = {"-o", "--output", "--compress-program"}
_GIT_MUTATING_OPTIONS = {
    "--output", "--ext-diff", "--open-files-in-pager", "--textconv",
}
_SAR_MUTATING_OPTIONS = {"-o", "--output"}
_IPTABLES_MUTATING = {
    "-A", "--append", "-I", "--insert", "-D", "--delete", "-F", "--flush",
    "-P", "--policy", "-N", "--new-chain", "-X", "--delete-chain",
    "-R", "--replace", "-Z", "--zero", "-E", "--rename-chain",
}
_LOGINCTL_READ_ONLY = {
    "list-sessions", "list-users", "list-seats", "show-session", "show-user",
    "session-status", "user-status",
}
_SYSTEMD_ANALYZE_READ_ONLY = {
    "time", "blame", "critical-chain", "verify", "cat-config", "dot",
    "dump", "list-units", "unit-paths", "exit-status", "capability",
}
_RPM_QUERY = re.compile(r"^-(?:q|qa|qi|ql|qf|qc|qp|qR|V|Va|Vf|Vl|Vc|Vp|Vv|V|q)$", re.I)


@dataclass(frozen=True)
class BashDecision:
    classification: str
    reason: str
    policy_version: str = POLICY_VERSION
    segments: int = 0

    def as_dict(self) -> dict[str, str | int]:
        return {
            "classification": self.classification,
            "reason": self.reason,
            "policyVersion": self.policy_version,
            "segments": self.segments,
        }


def _iter_nodes(node: Any):
    yield node
    for attr in ("parts", "list", "command", "output", "heredoc"):
        child = getattr(node, attr, None)
        if isinstance(child, list):
            for item in child:
                if hasattr(item, "kind"):
                    yield from _iter_nodes(item)
        elif hasattr(child, "kind"):
            yield from _iter_nodes(child)


def _words(node: Any) -> list[str]:
    return [str(part.word) for part in getattr(node, "parts", [])
            if getattr(part, "kind", "") == "word"]


def _name(words: list[str]) -> str:
    return words[0].rsplit("/", 1)[-1].lower() if words else ""


def _awk_script_read_only(script: str) -> bool:
    """Accept simple awk programs that only print/read, never redirect/exec."""
    outside: list[str] = []
    quote = ""
    escaped = False
    for char in script:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in {">", "|"}:
            return False
        outside.append(char)
    text = "".join(outside)
    blocked = ("system", "getline", "@load", "close(", "fflush(")
    return not any(token in text for token in blocked)


def _awk_read_only(args: list[str]) -> bool:
    if not args:
        return False
    index = 0
    while index < len(args):
        item = args[index]
        if item in {"-f", "--file", "-i", "--include", "-E"} or item.startswith("--file="):
            return False
        if item in {"-v", "-F"}:
            index += 2
            continue
        if item.startswith("--assign=") or item.startswith("--field-separator="):
            index += 1
            continue
        if item == "--":
            index += 1
            continue
        if item.startswith("-"):
            index += 1
            continue
        return _awk_script_read_only(item)
    return False


def _journalctl_read_only(args: list[str]) -> bool:
    return not any(item == option or item.startswith(option + "=")
                   for item in args for option in _JOURNAL_MUTATING_OPTIONS)


def _systemctl_read_only(args: list[str]) -> bool:
    action = next((item for item in args if not item.startswith("-")), "")
    return action in _SYSTEMCTL_READ_ONLY


def _tail_read_only(args: list[str]) -> bool:
    return not any(item in _TAIL_FOLLOW_OPTIONS
                   or item.startswith("--follow=") for item in args)


def _ping_read_only(args: list[str]) -> bool:
    return any(item == "-c" or item.startswith("-c")
               or item == "--count" or item.startswith("--count=")
               or item == "-w" or item.startswith("-w")
               or item == "--deadline" or item.startswith("--deadline=")
               for item in args)


def _top_read_only(args: list[str]) -> bool:
    batch = any(item in {"-b", "--batch"} for item in args)
    iterations = any(item == "-n" or item.startswith("-n")
                     or item.startswith("--iterations=") for item in args)
    return batch and iterations


def _docker_read_only(args: list[str]) -> bool:
    if any(item in {"--version", "-v", "--help", "-h"} for item in args):
        return True
    first = next((item for item in args if not item.startswith("-")), "")
    if first in {"logs", "events"} and any(
            item in {"-f", "--follow"} or item.startswith("--follow=") for item in args):
        return False
    if first in {"version", "info"}:
        return True
    if first in _DOCKER_READ_ONLY:
        return True
    if first in {"network", "volume", "system"}:
        second = next((item for item in args[args.index(first) + 1:]
                       if not item.startswith("-")), "")
        return (first, second) in {
            ("network", "ls"), ("network", "inspect"),
            ("volume", "ls"), ("volume", "inspect"),
            ("system", "df"), ("system", "info"),
        }
    return False


def _kubectl_read_only(args: list[str]) -> bool:
    first = next((item for item in args if not item.startswith("-")), "")
    if first == "logs" and any(item in {"-f", "--follow"} or item.startswith("--follow=")
                               for item in args):
        return False
    if first == "get" and any(item in {"-w", "--watch"} for item in args):
        return False
    if first in {"version", "get", "describe", "logs", "top", "explain",
                 "api-resources", "api-versions", "cluster-info"}:
        return True
    if first == "auth" and "can-i" in args:
        return True
    if first == "config":
        return any(item in {"view", "current-context", "get-contexts"} for item in args)
    return False


def _assignments_read_only(node: Any) -> bool:
    parts = [part for part in getattr(node, "parts", [])]
    return bool(parts) and all(
        getattr(part, "kind", "") == "assignment" for part in parts
    )


def _command_read_only(words: list[str]) -> bool:
    name = _name(words)
    args = words[1:]
    if not name or name in _INTERPRETERS:
        return False
    if name == "command":
        return len(words) >= 2 and words[1] in {"-v", "-V"}
    if name not in _READ_ONLY_COMMANDS:
        return False
    if name == "systemctl":
        return _systemctl_read_only(args)
    if name == "journalctl":
        return _journalctl_read_only(args)
    if name == "awk":
        return _awk_read_only(args)
    if name == "tail":
        return _tail_read_only(args)
    if name == "ping":
        return _ping_read_only(args)
    if name == "top":
        return _top_read_only(args)
    if name == "docker":
        return _docker_read_only(args)
    if name == "kubectl":
        return _kubectl_read_only(args)
    if name == "git":
        return (bool(args) and args[0] in {"status", "log", "diff", "show"}
                and not any(item in _GIT_MUTATING_OPTIONS
                            or item.startswith("--output=") for item in args))
    if name == "find":
        return not any(item in _FIND_MUTATING for item in args)
    if name == "sort":
        return not any(item in _SORT_MUTATING_OPTIONS
                       or (item.startswith("-o") and not item.startswith("--"))
                       or item.startswith("--output=")
                       or item.startswith("--compress-program=") for item in args)
    if name == "sar":
        return not any(item in _SAR_MUTATING_OPTIONS
                       or (item.startswith("-o") and not item.startswith("--"))
                       or item.startswith("--output=") for item in args)
    if name in {"iostat", "mpstat", "pidstat"}:
        return not any(item == "-o" or item.startswith("-o") for item in args)
    if name == "file":
        return not any(item in {"-C", "--compile"} for item in args)
    if name == "hostname":
        if any(item in _HOSTNAME_MUTATING_OPTIONS for item in args):
            return False
        return not any(not item.startswith("-") for item in args)
    if name == "hostnamectl":
        return bool(args) and args[0] in {"status", "show"}
    if name == "date":
        return not any(item == "-s" or item.startswith("-s")
                       or item == "--set" or item.startswith("--set=")
                       for item in args)
    if name == "ip":
        return not any(item in _IP_MUTATING
                       or item in {"netns", "-batch", "--batch", "-force", "--force", "-b"}
                       or item.startswith("--batch=")
                       for item in args)
    if name == "rpm":
        return (not any(item == "--pipe" or item.startswith("--pipe=") for item in args)
                and any(_RPM_QUERY.match(item) for item in args))
    if name == "timedatectl":
        return not args or args[0] in {"status", "show", "--help", "-h"}
    if name == "localectl":
        return not args or args[0] in {"status", "show", "--help", "-h"}
    if name == "loginctl":
        return bool(args) and args[0] in _LOGINCTL_READ_ONLY
    if name == "systemd-analyze":
        return bool(args) and args[0] in _SYSTEMD_ANALYZE_READ_ONLY
    if name in {"iptables", "ip6tables"}:
        return (any(item in {"-L", "--list", "-S", "--list-rules"} for item in args)
                and not any(item in _IPTABLES_MUTATING for item in args))
    if name == "nft":
        return ("list" in args
                and not any(item in {"add", "delete", "flush", "insert", "replace", "create",
                                     "-f", "--file"} for item in args))
    if name == "firewall-cmd":
        if any(item in {"--reload", "--complete-reload", "--panic-on", "--panic-off",
                        "--lockdown-on", "--lockdown-off"} for item in args):
            return False
        return any(item == "--state" or item.startswith("--get-")
                   or item.startswith("--list-") or item.startswith("--query-")
                   for item in args)
    if name == "dpkg":
        return any(item in {"-l", "-L", "-s", "--list", "--status", "--contents",
                            "--get-selections"} for item in args)
    if name in {"apt", "apt-get", "yum", "dnf"}:
        return bool(args) and args[0] in {"list", "show", "search", "info", "policy",
                                          "check-update", "--version", "--help"}
    if name in {"curl", "wget", "openssl", "tee"}:
        return False
    return True


def classify_bash_command(command: str) -> dict[str, str | int]:
    """Classify one command without executing it.

    A command is READ_ONLY only when every simple command segment is in the
    read-only policy, no wrapper/redirection/heredoc is present, and the
    parser accepted the complete input.
    """
    value = str(command or "").strip()
    if not value:
        return BashDecision(MUTATING, "empty_command").as_dict()
    if len(value) > MAX_COMMAND_CHARS:
        return BashDecision(MUTATING, "command_too_long").as_dict()
    destructive = destructive_command_reason(value)
    if destructive:
        return BashDecision(DESTRUCTIVE, destructive).as_dict()
    try:
        trees = bashlex.parse(value)
    except Exception:
        return BashDecision(MUTATING, "command_parse_failed").as_dict()

    segments = 0
    for tree in trees:
        for node in _iter_nodes(tree):
            kind = getattr(node, "kind", "")
            if kind == "processsubstitution":
                return BashDecision(MUTATING, "process_substitution").as_dict()
            if kind == "commandsubstitution":
                # Descend instead of rejecting: the inner simple commands are
                # checked by this same loop.  A substitution is safe only when
                # every command inside it is safe and no write redirect exists.
                continue
            if kind == "redirect":
                redirect_type = str(getattr(node, "type", ""))
                output = getattr(getattr(node, "output", None), "word", "")
                descriptor_only = redirect_type in {">&", "<&"} and isinstance(
                    getattr(node, "output", None), int,
                )
                if (redirect_type not in {"<", "<<"}
                        and output != "/dev/null" and not descriptor_only):
                    return BashDecision(MUTATING, "output_redirect").as_dict()
                if redirect_type == "<<":
                    return BashDecision(MUTATING, "heredoc").as_dict()
            if kind != "command":
                continue
            segments += 1
            words = _words(node)
            if not words:
                if _assignments_read_only(node):
                    continue
                return BashDecision(MUTATING, "command_not_read_only",
                                    segments=segments).as_dict()
            if not _command_read_only(words):
                return BashDecision(MUTATING, "command_not_read_only",
                                    segments=segments).as_dict()
    if segments == 0:
        return BashDecision(MUTATING, "no_command").as_dict()
    return BashDecision(READ_ONLY, "", segments=segments).as_dict()
