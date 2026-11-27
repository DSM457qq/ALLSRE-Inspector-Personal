from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable
import json
import os
import platform
import shutil


AUTO = "auto"
NATIVE_HOST_METADATA = Path("ALLSRE/ws-terminal-hook/install-metadata.json")


def _first_file(candidates: Iterable[Path]) -> str | None:
    for candidate in candidates:
        try:
            path = candidate.expanduser()
            if path.is_file():
                return str(path.resolve())
        except OSError:
            continue
    return None


def _first_dir(candidates: Iterable[Path], marker: str | None = None) -> str | None:
    for candidate in candidates:
        try:
            path = candidate.expanduser()
            if path.is_dir() and (marker is None or (path / marker).is_file()):
                return str(path.resolve())
        except OSError:
            continue
    return None


def resolve_executable(value: str) -> str | None:
    """Resolve a configured executable name or path without invoking a shell."""
    path = Path(value).expanduser()
    if path.is_file():
        return str(path.resolve())
    found = shutil.which(value)
    if found:
        return str(Path(found).resolve())
    return None


def _native_host_metadata() -> dict[str, Any]:
    local_appdata = os.getenv("LOCALAPPDATA")
    if not local_appdata:
        return {}
    path = Path(local_appdata) / NATIVE_HOST_METADATA
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return value if value.get("schemaVersion") == 1 else {}


def resolve_chrome_executable(value: str, install_root: Path) -> str | None:
    if value.strip().lower() != AUTO:
        return resolve_executable(value)
    env_value = os.getenv("ALLSRE_CHROME_EXECUTABLE")
    if env_value:
        resolved = resolve_executable(env_value)
        if resolved:
            return resolved
    for command in ("chrome", "chrome.exe", "msedge", "msedge.exe", "chromium"):
        resolved = resolve_executable(command)
        if resolved:
            return resolved
    roots = [os.getenv("PROGRAMFILES"), os.getenv("PROGRAMFILES(X86)"), os.getenv("LOCALAPPDATA")]
    common = []
    for root in filter(None, roots):
        common.extend([
            Path(root) / "Google/Chrome/Application/chrome.exe",
            Path(root) / "Microsoft/Edge/Application/msedge.exe",
        ])
    found = _first_file(common)
    if found:
        return found
    playwright_root = Path(os.getenv("LOCALAPPDATA", "")) / "ms-playwright"
    if playwright_root.is_dir():
        found = _first_file(sorted(playwright_root.glob("chromium-*/chrome-win64/chrome.exe"), reverse=True))
        if found:
            return found
    return _first_file([
        install_root / "chrome/chrome.exe",
        install_root / "runtime/chrome/chrome.exe",
    ])


def resolve_node_executable(value: str, install_root: Path) -> str | None:
    if value.strip().lower() != AUTO:
        return resolve_executable(value)
    env_value = os.getenv("ALLSRE_NODE_EXECUTABLE")
    if env_value:
        resolved = resolve_executable(env_value)
        if resolved:
            return resolved
    resolved = resolve_executable("node")
    if resolved:
        return resolved
    found = _first_file([
        Path(os.getenv("PROGRAMFILES", "")) / "nodejs/node.exe",
        Path(os.getenv("LOCALAPPDATA", "")) / "Programs/nodejs/node.exe",
    ])
    return found or _first_file([install_root / "node/node.exe", install_root / "runtime/node/node.exe"])


def resolve_extension_path(value: str, install_root: Path) -> str | None:
    if value.strip().lower() != AUTO:
        return _first_dir([Path(value)], "manifest.json")
    env_value = os.getenv("ALLSRE_EXTENSION_PATH")
    if env_value:
        found = _first_dir([Path(env_value)], "manifest.json")
        if found:
            return found
    metadata_value = str(_native_host_metadata().get("extensionPath") or "")
    if metadata_value:
        found = _first_dir([Path(metadata_value)], "manifest.json")
        if found:
            return found
    return _first_dir([
        install_root / "browser-extensions/ws-terminal-hook",
        install_root.parent / "browser-extensions/ws-terminal-hook",
        install_root / "extensions/ws-terminal-hook",
    ], "manifest.json")


def resolve_entrypoint(value: str, install_root: Path) -> str | None:
    if value.strip().lower() != AUTO:
        path = Path(value).expanduser()
        path = path if path.is_absolute() else install_root / path
        return _first_file([path])
    env_value = os.getenv("ALLSRE_PLAYWRIGHT_MCP_ENTRYPOINT")
    if env_value:
        found = _first_file([Path(env_value)])
        if found:
            return found
    return _first_file([
        install_root / "node_modules/@playwright/mcp/cli.js",
        install_root.parent / "node_modules/@playwright/mcp/cli.js",
    ])


def apply_auto_discovery(raw: dict[str, Any], install_root: Path) -> dict[str, Any]:
    """Resolve only fields explicitly set to ``auto``; explicit values stay untouched."""
    chrome = raw.setdefault("chrome", {})
    opencode = raw.setdefault("opencode", {})
    browser = raw.setdefault("browser_agent", {})
    resolvers = (
        (chrome, "executable", resolve_chrome_executable),
        (chrome, "extension_path", resolve_extension_path),
        (opencode, "executable", lambda value, root: resolve_opencode_executable(value)),
        (browser, "opencode_executable", lambda value, root: resolve_opencode_executable(value)),
        (browser, "playwright_mcp_executable", resolve_node_executable),
        (browser, "playwright_mcp_entrypoint", resolve_entrypoint),
    )
    for section, key, resolver in resolvers:
        value = str(section.get(key) or "").strip()
        if value.lower() != AUTO:
            continue
        resolved = resolver(value, install_root)
        section[key] = resolved or AUTO
    return raw


def deployment_diagnostics(raw: dict[str, Any], install_root: Path) -> list[dict[str, str | bool]]:
    resolved = apply_auto_discovery(raw, install_root)
    chrome = dict(resolved.get("chrome") or {})
    opencode = dict(resolved.get("opencode") or {})
    browser = dict(resolved.get("browser_agent") or {})
    checks = [
        ("CHROME_NOT_FOUND", "chrome.executable", resolve_chrome_executable(str(chrome.get("executable") or AUTO), install_root)),
        ("OPENCODE_NOT_FOUND", "opencode.executable", resolve_opencode_executable(str(opencode.get("executable") or "opencode"))),
        ("NODE_NOT_FOUND", "browser_agent.playwright_mcp_executable", resolve_node_executable(str(browser.get("playwright_mcp_executable") or "node"), install_root)),
        ("PLAYWRIGHT_MCP_NOT_FOUND", "browser_agent.playwright_mcp_entrypoint", resolve_entrypoint(str(browser.get("playwright_mcp_entrypoint") or "node_modules/@playwright/mcp/cli.js"), install_root)),
        ("TERMINAL_EXTENSION_NOT_FOUND", "chrome.extension_path", resolve_extension_path(str(chrome.get("extension_path") or AUTO), install_root)),
    ]
    return [{"ok": bool(path), "code": "OK" if path else code, "name": name, "path": path or ""} for code, name, path in checks]


def resolve_opencode_executable(value: str = "opencode") -> str | None:
    """Resolve OpenCode V1/V2, including npm platform-package layouts.

    A partially completed npm installation can contain ``opencode-ai`` but no
    top-level command shim.  Its real binary is still available in the
    platform-specific optional dependency, so use that binary directly.
    """
    requested = "opencode" if value.strip().lower() == AUTO else value
    env_value = os.getenv("ALLSRE_OPENCODE_EXECUTABLE") if value.strip().lower() == AUTO else None
    try:
        resolved = resolve_executable(env_value or requested)
    # Tests and some embedded hosts can intentionally emulate a different OS
    # path implementation. Discovery below is still safe in that situation.
    except Exception:  # path backend can be intentionally emulated in diagnostics tests
        resolved = None
    if resolved:
        unwrapped = _unwrap_npm_launcher(Path(resolved))
        if _usable_file(unwrapped):
            return str(unwrapped.resolve())

    # Only apply package discovery to the default command name. An explicit
    # but invalid path must not silently select another installation.
    if requested.strip().lower() not in {"opencode", "opencode.exe", "opencode.cmd"}:
        return None
    for package_root in _npm_opencode_roots():
        candidate = _platform_binary(package_root)
        if candidate is not None:
            return str(candidate.resolve())
    return None


def _unwrap_npm_launcher(path: Path) -> Path:
    if os.name != "nt" or path.suffix.lower() not in {".cmd", ".ps1"}:
        return path
    node_modules = path.parent / "node_modules"
    for package_root in (node_modules / "@opencode" / "cli", node_modules / "opencode-ai"):
        resolved = _platform_binary(package_root)
        if resolved is not None:
            return resolved
    return path


def _npm_opencode_roots() -> list[Path]:
    roots: list[Path] = []
    prefix = os.getenv("npm_config_prefix")
    if prefix:
        roots.extend((Path(prefix) / "node_modules" / "@opencode" / "cli",
                      Path(prefix) / "node_modules" / "opencode-ai"))
    appdata = os.getenv("APPDATA")
    if appdata:
        roots.extend((Path(appdata) / "npm" / "node_modules" / "@opencode" / "cli",
                      Path(appdata) / "npm" / "node_modules" / "opencode-ai"))
    local_appdata = os.getenv("LOCALAPPDATA")
    if local_appdata:
        roots.extend((Path(local_appdata) / "npm" / "node_modules" / "@opencode" / "cli",
                      Path(local_appdata) / "npm" / "node_modules" / "opencode-ai"))
    return list(dict.fromkeys(roots))


def _platform_binary(package_root: Path) -> Path | None:
    if os.name != "nt":
        direct = package_root / "bin" / "opencode"
        return direct if _usable_file(direct) else None
    machine = platform.machine().lower()
    architecture = "arm64" if machine in {"arm64", "aarch64"} else "x64"
    names = [
        f"@opencode/cli-windows-{architecture}",
        f"@opencode/cli-windows-{architecture}-baseline",
        f"opencode-windows-{architecture}",
        f"opencode-windows-{architecture}-baseline",
    ]
    for name in names:
        candidate = package_root / "node_modules" / name / "bin" / "opencode.exe"
        if _usable_file(candidate):
            return candidate
    direct = package_root / "bin" / "opencode.exe"
    return direct if _usable_file(direct) else None


def _usable_file(path: Path) -> bool:
    try:
        # The npm package initially writes a small textual failure stub here.
        return path.is_file() and path.stat().st_size > 4096
    except OSError:
        return False
