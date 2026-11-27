from __future__ import annotations

from typing import Any, Iterable
import re

import bashlex


_SECRET_KEY = re.compile(r"(password|secret|token|authorization)", re.IGNORECASE)
_PERMANENTLY_DANGEROUS = re.compile(
    r"(?:^|[;&|]\s*)(?:"
    r"mkfs(?:\.\w+)?|fdisk|parted|sfdisk|wipefs|shutdown|reboot|poweroff|halt|"
    r"useradd|userdel|usermod|passwd|chpasswd|ssh-keygen|"
    r"dd\s+.*\bof=/dev/|rm\s+-(?=[A-Za-z]*r)(?=[A-Za-z]*f)[A-Za-z]+\s+/(?:\s|$)|"
    r"(?:curl|wget)\b[^;&|]*(?:\||&&)\s*(?:sh|bash|zsh)|"
    r"(?:base64|xxd)\s+-d[^;&|]*(?:\||&&)\s*(?:sh|bash|zsh)"
    r")",
    re.IGNORECASE,
)
_SAFE_COMMANDS = {
    "awk", "basename", "cat", "command", "cut", "date", "df", "dirname", "dmesg",
    "du", "echo", "egrep", "false", "fgrep", "find", "free", "getent",
    "grep", "head", "hostname", "hostnamectl", "id", "ip", "journalctl", "ls",
    "lsblk", "lscpu", "lsof", "md5sum", "netstat", "nproc", "openssl", "pgrep",
    "printenv", "printf", "ps", "pwd", "readlink", "realpath", "rpm", "sed",
    "sha256sum", "sort", "ss", "stat", "systemctl", "tail", "test", "top", "tr",
    "true", "uname", "uniq", "uptime", "vmstat", "wc", "which",
    "apt", "apt-get", "dnf", "dpkg", "docker", "kubectl", "service", "yum",
    "firewall-cmd", "getenforce", "iptables", "nerdctl", "nft", "sestatus",
    "sleep",
}
_WRAPPERS = {
    "bash", "sh", "zsh", "dash", "eval", "exec", "source", ".", "xargs",
    "python", "python3", "perl", "ruby", "node", "sudo", "su",
}
_PACKAGE_ACTIONS = {
    "install", "remove", "erase", "purge", "upgrade", "update",
    "dist-upgrade", "autoremove", "downgrade", "uninstall", "add",
}
_SERVICE_ACTIONS = {
    "start", "stop", "restart", "reload", "enable", "disable", "mask", "unmask",
}


def _walk(node):
    yield node
    for attribute in ("parts", "list", "command", "output", "heredoc"):
        child = getattr(node, attribute, None)
        if isinstance(child, list):
            for item in child:
                if hasattr(item, "kind"):
                    yield from _walk(item)
        elif hasattr(child, "kind"):
            yield from _walk(child)


def _command_words(node) -> list[str]:
    return [
        str(part.word) for part in getattr(node, "parts", [])
        if getattr(part, "kind", "") == "word"
    ]


def _required_capability(words: list[str]) -> str | None:
    if not words:
        return None
    name = words[0].rsplit("/", 1)[-1].lower()
    args = [item.lower() for item in words[1:]]
    if name in {"rm", "unlink", "rmdir"}:
        return "FILE_DELETE"
    if name in {"cp", "mv", "touch", "mkdir", "install"}:
        return "FILE_WRITE"
    if name == "tee" or (name == "sed" and any(x == "-i" or x.startswith("-i") for x in args)):
        return "FILE_WRITE"
    if name in {"chmod", "chown", "chgrp", "setfacl"}:
        return "PERMISSION_CHANGE"
    if name in {"kill", "pkill", "killall"}:
        return "SERVICE_CONTROL"
    if name == "systemctl" and any(x in _SERVICE_ACTIONS for x in args):
        return "SERVICE_CONTROL"
    if name == "service" and any(x in _SERVICE_ACTIONS for x in args):
        return "SERVICE_CONTROL"
    if name in {"apt", "apt-get", "yum", "dnf", "pip", "pip3", "npm", "pnpm", "yarn"}:
        if any(x in _PACKAGE_ACTIONS for x in args):
            return "PACKAGE_MANAGEMENT"
    if name == "rpm" and any(
        x in {"--install", "--upgrade", "--erase", "--remove", "--freshen"}
        or re.fullmatch(r"-(?:i|u|e|f)[vh]*", x)
        for x in args
    ):
        return "PACKAGE_MANAGEMENT"
    if name == "dpkg" and any(
        x in {"--install", "--remove", "--purge", "--unpack", "--configure"}
        or re.fullmatch(r"-(?:i|r|p)", x)
        for x in args
    ):
        return "PACKAGE_MANAGEMENT"
    return None


def _query_command_denial(words: list[str]) -> str | None:
    if not words:
        return None
    name = words[0].rsplit("/", 1)[-1].lower()
    args = [item.lower() for item in words[1:]]
    if name in {"docker", "nerdctl"}:
        if not args:
            return None
        # Informational client options are safe in READ_ONLY mode.
        if any(item in {"--version", "-v", "--help", "-h"} for item in args):
            return None
        first = next((item for item in args if not item.startswith("-")), "")
        if first in {
            "version", "info", "ps", "images", "inspect", "stats", "logs",
            "top", "port", "events",
        }:
            return None
        if first in {"network", "volume", "system"}:
            second = next(
                (item for item in args[args.index(first) + 1:] if not item.startswith("-")),
                "",
            )
            if (first, second) in {
                ("network", "ls"), ("network", "inspect"),
                ("volume", "ls"), ("volume", "inspect"), ("system", "df"),
            }:
                return None
        return "container_mutation_not_permitted"
    if name == "kubectl":
        first = next((item for item in args if not item.startswith("-")), "")
        if first in {
            "version", "get", "describe", "logs", "top", "explain",
            "api-resources", "api-versions", "cluster-info",
        }:
            return None
        if first == "auth" and "can-i" in args:
            return None
        if first == "config" and any(
            item in {"view", "current-context", "get-contexts"} for item in args
        ):
            return None
        return "kubernetes_mutation_not_permitted"
    if name == "systemctl":
        if any(item in _SERVICE_ACTIONS for item in args):
            return None
        if any(
            item in {
                "status", "show", "is-active", "is-enabled", "is-failed",
                "list-units", "list-unit-files", "list-dependencies",
            }
            for item in args
        ):
            return None
        return "systemctl_action_not_permitted"
    if name == "service":
        if any(item in _SERVICE_ACTIONS for item in args):
            return None
        if any(item in {"status", "--status-all"} for item in args):
            return None
        return "service_action_not_permitted"
    if name == "iptables":
        return None if any(
            item in {"-l", "--list", "-s", "--list-rules"} for item in args
        ) else "firewall_mutation_not_permitted"
    if name == "nft":
        return None if args and args[0] == "list" else "firewall_mutation_not_permitted"
    if name == "firewall-cmd":
        return None if any(
            item == "--state"
            or item.startswith("--get-")
            or item.startswith("--list-")
            or item.startswith("--query-")
            for item in args
        ) else "firewall_mutation_not_permitted"
    return None


_DESTRUCTIVE = re.compile(
    r"(?:^|[;&|]\s*)(?:"
    r"mkfs(?:\.\w+)?|wipefs|fdisk|sfdisk|parted\s+.*\b(?:mklabel|rm)\b|"
    r"dd\s+[^;&|]*\bof=/dev/(?:sd|nvme|vd|hd|mmcblk)|"
    r"rm\s+-(?=[A-Za-z]*r)(?=[A-Za-z]*f)[A-Za-z]+\s+/(?:\s|$)|"
    r"shutdown|reboot|poweroff|halt|init\s+[06]|"
    r"drop\s+(?:database|table)|truncate\s+table|"
    r"chmod\s+-R\s+000\s+/\s*$|chown\s+-R\s+\S+\s+/\s*$"
    r")",
    re.IGNORECASE,
)


def destructive_command_reason(command: str) -> str | None:
    """Hard-deny irreversible destructive commands regardless of policy."""
    return "permanently_destructive_command" if _DESTRUCTIVE.search(command) else None


def command_denial_reason(
    command: str, execution_mode: str, capabilities: Iterable[str] = (),
) -> str | None:
    if execution_mode not in {"READ_ONLY", "CHANGE"}:
        return "invalid_execution_mode"
    if _PERMANENTLY_DANGEROUS.search(command):
        return "permanently_dangerous_command"
    try:
        trees = bashlex.parse(command)
    except (ValueError, NotImplementedError):
        return "shell_parse_failed"
    allowed = set(capabilities)
    for tree in trees:
        for node in _walk(tree):
            kind = getattr(node, "kind", "")
            if kind == "redirect":
                redirect_type = str(getattr(node, "type", ""))
                output = getattr(getattr(node, "output", None), "word", "")
                # File descriptor duplication (for example ``2>&1``) does not
                # write a new path. Discarding output to /dev/null is likewise
                # safe in READ_ONLY mode.
                descriptor_only = redirect_type in {">&", "<&"} and isinstance(
                    getattr(node, "output", None), int
                )
                if (
                    redirect_type not in {"<", "<<"}
                    and output != "/dev/null"
                    and not descriptor_only
                ):
                    if execution_mode == "READ_ONLY" or "FILE_WRITE" not in allowed:
                        return "capability_required:FILE_WRITE"
                if redirect_type == "<<":
                    return "heredoc_not_permitted"
            if kind != "command":
                continue
            words = _command_words(node)
            if not words:
                continue
            name = words[0].rsplit("/", 1)[-1].lower()
            if name in _WRAPPERS:
                return "command_wrapper_not_permitted"
            if name == "command" and (len(words) < 2 or words[1] not in {"-v", "-V"}):
                return "command_wrapper_not_permitted"
            if name == "find" and any(
                x in {"-delete", "-exec", "-execdir", "-ok", "-okdir"} for x in words[1:]
            ):
                return "command_wrapper_not_permitted"
            if name == "awk" and any("system(" in x.replace(" ", "") for x in words[1:]):
                return "command_wrapper_not_permitted"
            specific_denial = _query_command_denial(words)
            if specific_denial:
                return specific_denial
            capability = _required_capability(words)
            if capability:
                if execution_mode == "READ_ONLY":
                    return "read_only_mode"
                if capability not in allowed:
                    return f"capability_required:{capability}"
            elif name not in _SAFE_COMMANDS:
                return "unclassified_command"
    return None


BASH_CLASSIFICATION_READ_ONLY = "READ_ONLY"
BASH_CLASSIFICATION_MUTATING = "MUTATING"
BASH_CLASSIFICATION_DESTRUCTIVE = "DESTRUCTIVE"
MAX_CLASSIFIED_COMMAND_CHARS = 16_000


def classify_bash_command(command: str) -> dict[str, str | int]:
    """Compatibility wrapper for the independent read-only policy."""
    from .readonly_policy import classify_bash_command as _classify
    return _classify(command)

def command_is_mutating(command: str) -> bool:
    reason = command_denial_reason(command, "READ_ONLY")
    return reason in {
        "read_only_mode",
        "capability_required:FILE_WRITE",
        "capability_required:FILE_DELETE",
        "capability_required:PACKAGE_MANAGEMENT",
        "capability_required:SERVICE_CONTROL",
        "capability_required:PERMISSION_CHANGE",
    } or reason == "unclassified_command"


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): ("***" if _SECRET_KEY.search(str(key)) else redact(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value
