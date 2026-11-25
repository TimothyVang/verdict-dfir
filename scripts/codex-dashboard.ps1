param(
    [int]$Port = 3000,
    [switch]$NoOpen
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$CodexUrl = "http://localhost:$Port/codex"
$LogDir = Join-Path $env:LOCALAPPDATA "Temp\opencode"
$OutLog = Join-Path $LogDir "findevil-codex-dashboard.out"
$ErrLog = Join-Path $LogDir "findevil-codex-dashboard.err"

New-Item -ItemType Directory -Force $LogDir | Out-Null

function Test-CodexDashboard {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $CodexUrl -TimeoutSec 3
        return $response.StatusCode -eq 200
    } catch {
        return $false
    }
}

if (-not (Test-CodexDashboard)) {
    $env:FINDEVIL_CODEX_UI_ENABLE = "1"
    Start-Process `
        -FilePath "pnpm" `
        -ArgumentList @("--filter", "@findevil/web", "dev", "--", "--port", "$Port") `
        -WorkingDirectory $RepoRoot `
        -RedirectStandardOutput $OutLog `
        -RedirectStandardError $ErrLog `
        -WindowStyle Hidden | Out-Null

    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        if (Test-CodexDashboard) { break }
        Start-Sleep -Milliseconds 500
    }
}

if (-not (Test-CodexDashboard)) {
    Write-Error "Find Evil dashboard did not start. Logs: $OutLog $ErrLog"
}

if (-not $NoOpen) {
    Start-Process $CodexUrl | Out-Null
}

Write-Output "Dashboard is running:"
Write-Output "- Codex cockpit: $CodexUrl"
Write-Output "- Audit dashboard: http://localhost:$Port/"
Write-Output "- Debug stream: http://localhost:$Port/debug"
Write-Output "- Logs: $OutLog $ErrLog"
