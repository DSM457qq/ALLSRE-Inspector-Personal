from __future__ import annotations

from pathlib import Path
from typing import Any, AsyncIterable, AsyncIterator
import os

from ..core.errors import ServiceError


CHUNK_SIZE = 1024 * 1024


def _safe_path(root: Path, rel_path: str) -> Path:
    """Confine ``rel_path`` under ``root``, rejecting ``..`` and absolute escapes."""
    raw = str(rel_path or "").replace("\\", "/")
    # Reject absolute POSIX paths and Windows drive-letter paths outright rather
    # than silently re-rooting them; the resolve + parents check below then
    # handles any ``..`` traversal that still lands outside ``root``.
    if raw.startswith("/") or (len(raw) >= 2 and raw[1] == ":"):
        raise ServiceError(400, "path_escape", {"code": "path_escape"})
    path = (root / raw).resolve()
    if path != root and root not in path.parents:
        raise ServiceError(400, "path_escape", {"code": "path_escape"})
    return path


class FileStorageService:
    """Staging-area file exchange with the config-center.

    Files are addressed by a path relative to ``root`` (the worker desktop
    ``ALLSRE-files`` folder by default). Transfer is streamed in fixed chunks
    so large files never need to be buffered in memory.
    """

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def list_dir(self, rel_path: str = "") -> list[dict[str, Any]]:
        directory = _safe_path(self.root, rel_path)
        if not directory.is_dir():
            raise ServiceError(404, "path_not_found", {"code": "path_not_found"})
        entries: list[dict[str, Any]] = []
        for child in sorted(directory.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
            try:
                stat = child.stat()
            except OSError:
                continue
            entries.append({
                "name": child.name,
                "type": "dir" if child.is_dir() else "file",
                "size": stat.st_size,
                "mtime": int(stat.st_mtime),
            })
        return entries

    async def write_stream(self, rel_path: str, chunks: AsyncIterable[bytes]) -> int:
        target = _safe_path(self.root, rel_path)
        if target.is_dir():
            raise ServiceError(409, "path_is_directory", {"code": "path_is_directory"})
        target.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with open(target, "wb") as handle:
            async for chunk in chunks:
                handle.write(chunk)
                written += len(chunk)
        return written

    def write_text(self, rel_path: str, content: str) -> dict[str, Any]:
        """Write one UTF-8 task artifact inside the configured staging root."""
        target = _safe_path(self.root, rel_path)
        if target.is_dir():
            raise ServiceError(409, "path_is_directory", {"code": "path_is_directory"})
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = content.encode("utf-8")
        written = target.write_bytes(payload)
        return {"path": target.relative_to(self.root).as_posix(), "size": written}

    async def read_stream(self, rel_path: str, offset: int = 0) -> AsyncIterator[bytes]:
        target = _safe_path(self.root, rel_path)
        if not target.is_file():
            raise ServiceError(404, "path_not_found", {"code": "path_not_found"})
        with open(target, "rb") as handle:
            if offset:
                handle.seek(offset)
            while chunk := handle.read(CHUNK_SIZE):
                yield chunk

    def stat(self, rel_path: str) -> dict[str, Any]:
        target = _safe_path(self.root, rel_path)
        if not target.exists():
            return {"exists": False}
        return {
            "exists": True,
            "size": target.stat().st_size,
            "type": "dir" if target.is_dir() else "file",
            "mtime": int(target.stat().st_mtime),
        }

    def remove(self, rel_path: str) -> None:
        target = _safe_path(self.root, rel_path)
        if target.is_dir():
            raise ServiceError(409, "path_is_directory", {"code": "path_is_directory"})
        if not target.exists():
            raise ServiceError(404, "path_not_found", {"code": "path_not_found"})
        os.remove(target)
