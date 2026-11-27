"""Bounded file transfer over an already-authorised interactive shell.

This is a compatibility transport for bastion terminals which cannot expose
SFTP.  It deliberately does not try to become a general file API: callers can
only address absolute, non-traversing paths and every byte still travels
through the terminal session that the asset-access workflow opened.
"""
from __future__ import annotations

import base64
import re
import shlex
import uuid
from typing import Any, Protocol


BASE64_TRANSFER_MAX_BYTES = 16 * 1024 * 1024
_CHUNK_BYTES = 12 * 1024  # Base64 expands this to 16 KiB shell arguments.


class _ShellTerminal(Protocol):
    def execute(self, command: str, timeout: int = 30) -> dict[str, Any]: ...


def _remote_path(value: str) -> str:
    windows_absolute = bool(re.match(r"^[A-Za-z]:[\\/]", value))
    parts = re.split(r"[\\/]", value)
    if (not value.startswith("/") and not windows_absolute) or ".." in parts:
        raise ValueError("ansible_bridge_remote_path_invalid")
    return value


def _require_ok(result: dict[str, Any], code: str) -> str:
    exit_code = result.get("exit_code")
    if exit_code not in (None, 0):
        raise RuntimeError(code)
    return str(result.get("output") or "")


class Base64ShellTransfer:
    """Mixin for terminal adapters that provide a POSIX-like ``execute``.

    The target needs ``sh``, ``base64``, ``mv`` and ``rm``.  A missing command
    is surfaced as a bounded transport error; no credentials or file content
    are placed in errors or logs.
    """

    def execute(self, command: str, timeout: int = 30) -> dict[str, Any]:
        raise NotImplementedError

    def _transfer_mode(self) -> str:
        cached = getattr(self, "_allsre_base64_transfer_mode", "")
        if cached:
            return cached
        posix = self.execute("command -v base64 >/dev/null 2>&1", 10)
        if posix.get("exit_code") in (None, 0):
            mode = "posix"
        else:
            windows = self.execute("powershell -NoProfile -NonInteractive -Command \"$PSVersionTable.PSVersion.Major\"", 15)
            if windows.get("exit_code") not in (None, 0):
                raise RuntimeError("ansible_bridge_base64_transport_unavailable")
            mode = "powershell"
        setattr(self, "_allsre_base64_transfer_mode", mode)
        return mode

    @staticmethod
    def _ps(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    def upload_bytes(self, remote_path: str, content: bytes) -> None:
        remote = _remote_path(remote_path)
        if len(content) > BASE64_TRANSFER_MAX_BYTES:
            raise ValueError("ansible_bridge_file_too_large")
        mode = self._transfer_mode()
        parent = remote.rsplit("/", 1)[0] or "/"
        temporary = f"{remote}.allsre-{uuid.uuid4().hex}.tmp"
        quoted_temp, quoted_remote = shlex.quote(temporary), shlex.quote(remote)
        try:
            if mode == "powershell":
                self._upload_powershell(remote, temporary, content)
                return
            _require_ok(
                self.execute(f"mkdir -p -- {shlex.quote(parent)} && : > {quoted_temp}", 30),
                "ansible_bridge_base64_prepare_failed",
            )
            for offset in range(0, len(content), _CHUNK_BYTES):
                encoded = base64.b64encode(content[offset:offset + _CHUNK_BYTES]).decode("ascii")
                _require_ok(
                    self.execute(f"printf %s {shlex.quote(encoded)} | base64 -d >> {quoted_temp}", 30),
                    "ansible_bridge_base64_upload_failed",
                )
            _require_ok(
                self.execute(f"mv -f -- {quoted_temp} {quoted_remote}", 30),
                "ansible_bridge_base64_commit_failed",
            )
        except Exception:
            try:
                self.execute(f"rm -f -- {quoted_temp}", 15)
            except Exception:
                pass
            raise

    def download_bytes(self, remote_path: str, max_bytes: int = BASE64_TRANSFER_MAX_BYTES) -> bytes:
        remote = _remote_path(remote_path)
        limit = min(max(0, int(max_bytes)), BASE64_TRANSFER_MAX_BYTES)
        if self._transfer_mode() == "powershell":
            return self._download_powershell(remote, limit)
        quoted = shlex.quote(remote)
        size_output = _require_ok(
            self.execute(f"test -r {quoted} && wc -c < {quoted}", 30),
            "ansible_bridge_base64_stat_failed",
        )
        sizes = re.findall(r"(?<!\d)(\d+)(?!\d)", size_output)
        if not sizes:
            raise RuntimeError("ansible_bridge_base64_stat_invalid")
        if int(sizes[-1]) > limit:
            raise ValueError("ansible_bridge_file_too_large")
        begin, end = "__ALLSRE_B64_BEGIN__", "__ALLSRE_B64_END__"
        output = _require_ok(
            self.execute(
                f"printf '{begin}\\n'; base64 < {quoted}; printf '\\n{end}\\n'", 120,
            ),
            "ansible_bridge_base64_download_failed",
        )
        match = re.search(re.escape(begin) + r"\s*(.*?)\s*" + re.escape(end), output, re.S)
        if not match:
            raise RuntimeError("ansible_bridge_base64_download_invalid")
        try:
            return base64.b64decode(re.sub(r"\s+", "", match.group(1)), validate=True)
        except Exception as exc:
            raise RuntimeError("ansible_bridge_base64_download_invalid") from exc

    def _upload_powershell(self, remote: str, temporary: str, content: bytes) -> None:
        ps_tmp, ps_remote = self._ps(temporary), self._ps(remote)
        prepare = (
            f"$p={ps_tmp}; New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null; "
            "[IO.File]::WriteAllBytes($p,[byte[]]@())"
        )
        _require_ok(self.execute(f"powershell -NoProfile -NonInteractive -Command {shlex.quote(prepare)}", 30),
                    "ansible_bridge_base64_prepare_failed")
        try:
            for offset in range(0, len(content), _CHUNK_BYTES):
                encoded = base64.b64encode(content[offset:offset + _CHUNK_BYTES]).decode("ascii")
                append = (
                    f"$b=[Convert]::FromBase64String({self._ps(encoded)}); $s=[IO.File]::Open({ps_tmp},[IO.FileMode]::Append); "
                    "$s.Write($b,0,$b.Length); $s.Dispose()"
                )
                _require_ok(self.execute(f"powershell -NoProfile -NonInteractive -Command {shlex.quote(append)}", 30),
                            "ansible_bridge_base64_upload_failed")
            move = f"Move-Item -Force -LiteralPath {ps_tmp} -Destination {ps_remote}"
            _require_ok(self.execute(f"powershell -NoProfile -NonInteractive -Command {shlex.quote(move)}", 30),
                        "ansible_bridge_base64_commit_failed")
        except Exception:
            self.execute(f"powershell -NoProfile -NonInteractive -Command {shlex.quote(f'Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath {ps_tmp}')} ", 15)
            raise

    def _download_powershell(self, remote: str, limit: int) -> bytes:
        ps_remote = self._ps(remote)
        length = _require_ok(self.execute(
            f"powershell -NoProfile -NonInteractive -Command {shlex.quote(f'(Get-Item -LiteralPath {ps_remote}).Length')}", 30,
        ), "ansible_bridge_base64_stat_failed")
        sizes = re.findall(r"(?<!\d)(\d+)(?!\d)", length)
        if not sizes:
            raise RuntimeError("ansible_bridge_base64_stat_invalid")
        if int(sizes[-1]) > limit:
            raise ValueError("ansible_bridge_file_too_large")
        command = f"[Console]::WriteLine('__ALLSRE_B64_BEGIN__'); [Console]::WriteLine([Convert]::ToBase64String([IO.File]::ReadAllBytes({ps_remote}))); [Console]::WriteLine('__ALLSRE_B64_END__')"
        output = _require_ok(self.execute(
            f"powershell -NoProfile -NonInteractive -Command {shlex.quote(command)}", 120,
        ), "ansible_bridge_base64_download_failed")
        match = re.search(r"__ALLSRE_B64_BEGIN__\s*(.*?)\s*__ALLSRE_B64_END__", output, re.S)
        if not match:
            raise RuntimeError("ansible_bridge_base64_download_invalid")
        try:
            return base64.b64decode(re.sub(r"\s+", "", match.group(1)), validate=True)
        except Exception as exc:
            raise RuntimeError("ansible_bridge_base64_download_invalid") from exc
