# Start ALLSRE Inspector Personal without a console window.
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$python = Join-Path $root ".venv\Scripts\python.exe"
$config = Join-Path $root "inspector.yaml"
$pidFile = Join-Path $root "data\personal.pid"

if (-not (Test-Path $python)) { throw "missing venv: $python" }
if (-not (Test-Path $config)) { throw "missing config: $config" }
New-Item -ItemType Directory -Force -Path (Split-Path $pidFile) | Out-Null

if (Test-Path $pidFile) {
    $old = [int](Get-Content $pidFile -Raw)
    if (Get-Process -Id $old -ErrorAction SilentlyContinue) {
        "ALLSRE Inspector Personal already running (PID $old)"
        exit 0
    }
    Remove-Item $pidFile -Force
}

$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $python
$psi.Arguments = '-m allsre_inspector.personal.main --config "' + $config + '"'
$psi.WorkingDirectory = $root
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$process = [System.Diagnostics.Process]::Start($psi)
Set-Content -Path $pidFile -Value $process.Id -Encoding ascii

Start-Sleep -Seconds 6
$health = curl.exe -sS -m 5 http://127.0.0.1:8876/health 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Inspector did not become healthy; check logs and config"
}
"ALLSRE Inspector Personal started (PID $($process.Id))"
$health
