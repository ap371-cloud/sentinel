<#
    Resets the SENTINEL demo instance to a freshly seeded state.

    Stops the API and the Vite dev server first: api_smoke.py and the running
    server share data/, keys/, ledger/ and evidence/, so wiping those underneath a
    live process is what produces the confusing "no such file / UNIQUE constraint"
    failures.

    Usage:
        powershell -ExecutionPolicy Bypass -File scripts\reset_demo.ps1
        powershell -ExecutionPolicy Bypass -File scripts\reset_demo.ps1 -KeepRunning
#>

[CmdletBinding()]
param(
    # Leave the servers down afterwards so the caller can start them deliberately.
    [switch]$KeepRunning
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $py)) {
    throw "Virtual environment not found at $py"
}

function Stop-ListeningProcess {
    param([int]$Port, [string]$Label)

    $listeners = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if (-not $listeners) {
        Write-Host "  $Label : nothing listening on $Port"
        return
    }
    foreach ($pid_ in ($listeners | Select-Object -ExpandProperty OwningProcess -Unique)) {
        Stop-Process -Id $pid_ -Force -ErrorAction SilentlyContinue
        Write-Host "  $Label : stopped pid $pid_ on port $Port"
    }
}

Write-Host 'Stopping servers'
Stop-ListeningProcess -Port 8000 -Label 'api'
Stop-ListeningProcess -Port 5173 -Label 'ui'
Start-Sleep -Seconds 2

$folders = @('data', 'keys', 'ledger', 'evidence')
Write-Host 'Removing runtime state'
foreach ($folder in $folders) {
    $target = Join-Path $root $folder
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
        Write-Host "  removed $folder\"
    }
    New-Item -ItemType Directory -Path $target -Force | Out-Null
}

if ($KeepRunning) {
    Write-Host 'Reset complete. Servers left stopped.'
    exit 0
}

Write-Host 'Starting API (first boot generates post-quantum keys, expect ~60s)'
$apiLog = Join-Path $env:TEMP 'sentinel_api.log'
$apiErr = Join-Path $env:TEMP 'sentinel_api.err'
Start-Process -FilePath $py `
    -ArgumentList '-m', 'uvicorn', 'app.main:app', '--app-dir', 'backend', '--host', '127.0.0.1', '--port', '8000' `
    -WorkingDirectory $root -WindowStyle Hidden `
    -RedirectStandardOutput $apiLog -RedirectStandardError $apiErr

Write-Host 'Waiting for the ledger to come online'
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 3
    try {
        $health = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/health' -TimeoutSec 5
        if ($health.status -eq 'UP') { $ready = $true; break }
    } catch {
        # still booting
    }
}
if (-not $ready) {
    Write-Host "API did not come up. See $apiErr"
    exit 1
}

Write-Host 'Starting UI dev server'
$node = 'C:\Program Files\nodejs\node.exe'
$frontend = Join-Path $root 'frontend'
$uiLog = Join-Path $env:TEMP 'sentinel_ui.log'
$uiErr = Join-Path $env:TEMP 'sentinel_ui.err'
Start-Process -FilePath $node `
    -ArgumentList 'node_modules\vite\bin\vite.js', '--host', '127.0.0.1', '--port', '5173', '--strictPort' `
    -WorkingDirectory $frontend -WindowStyle Hidden `
    -RedirectStandardOutput $uiLog -RedirectStandardError $uiErr

Start-Sleep -Seconds 8
Write-Host ''
Write-Host 'Demo instance ready'
Write-Host '  UI      http://127.0.0.1:5173'
Write-Host '  API     http://127.0.0.1:8000'
Write-Host '  Docs    http://127.0.0.1:8000/api/docs'
Write-Host '  Sign in COMMANDER-001 / Commander!2026'