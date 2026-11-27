# Stop ALLSRE Inspector Personal and its OpenCode child processes.
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$pidFile = Join-Path $root "data\personal.pid"

if (-not (Test-Path $pidFile)) {
    "No PID file; Inspector is not running (or was started manually)."
    exit 0
}

$processId = [int](Get-Content $pidFile -Raw)
if (Get-Process -Id $processId -ErrorAction SilentlyContinue) {
    & taskkill.exe /PID $processId /T /F | Out-Null
    "ALLSRE Inspector Personal stopped (PID $processId)"
} else {
    "PID $processId is no longer running"
}
Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
