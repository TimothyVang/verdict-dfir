# run-all-smokes.ps1 - native Windows smoke/lint/test gate.
#
# Mirrors scripts/run-all-smokes.sh without using bash as the runner. Most
# checks stay Windows-native; launcher-smoke still requires a Git Bash `bash`
# on PATH for `bash -n` syntax checks.

[CmdletBinding()]
param(
    [switch]$SkipSlowRust
)

$ErrorActionPreference = "Continue"

$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $repo

$script:passed = 0
$script:failed = 0
$script:skipped = 0

function Test-CommandAvailable {
    param([Parameter(Mandatory = $true)][string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-PythonCommand {
    foreach ($candidate in @("python", "python3")) {
        if (Test-CommandAvailable $candidate) { return $candidate }
    }
    return ""
}

function Invoke-Smoke {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Command,
        [scriptblock]$Prereq = { $true }
    )

    ""
    "--- $Label ---"

    $prereqOk = $false
    try {
        $prereqOk = [bool](& $Prereq)
    }
    catch {
        $prereqOk = $false
    }
    if (-not $prereqOk) {
        "  SKIP: prerequisite not met"
        $script:skipped += 1
        return
    }

    $started = Get-Date
    $global:LASTEXITCODE = 0
    try {
        & $Command
        $exitCode = $global:LASTEXITCODE
        if ($null -eq $exitCode) { $exitCode = if ($?) { 0 } else { 1 } }
    }
    catch {
        $_ | Out-String | Write-Error
        $exitCode = 1
    }

    $elapsed = [int]((Get-Date) - $started).TotalSeconds
    if ($exitCode -eq 0) {
        "  PASS: $Label (${elapsed}s)"
        $script:passed += 1
    }
    else {
        "  FAIL: $Label (${elapsed}s)"
        $script:failed += 1
    }
}

$python = Get-PythonCommand

"=========================================="
"Find Evil! - run all L1 smokes locally"
"=========================================="

$rustMcpSmoke = @{
    Label = "rust-mcp-smoke (32-tool catalog + core error paths)"
    Command = { & $python scripts/rust-mcp-smoke.py --release }
    Prereq = {
        $releaseDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repo "target" }
        $bin = Join-Path $releaseDir "release\findevil-mcp.exe"
        $plainBin = Join-Path $releaseDir "release\findevil-mcp"
        $python -and ((Test-Path -LiteralPath $bin -PathType Leaf) -or (Test-Path -LiteralPath $plainBin -PathType Leaf))
    }
}
Invoke-Smoke @rustMcpSmoke

$agentMcpSmoke = @{
    Label = "agent-mcp-smoke (synthetic Findings + crypto chain)"
    Command = { uv run --directory services/agent_mcp python ../../scripts/agent-mcp-smoke.py }
    Prereq = { (Test-CommandAvailable "uv") -and (Test-Path -LiteralPath "services/agent_mcp" -PathType Container) }
}
Invoke-Smoke @agentMcpSmoke

Invoke-Smoke -Label "verdict-policy-smoke (compute_verdict + detect_evidence_type)" -Command { & $python scripts/verdict-policy-smoke.py } -Prereq { $python }
Invoke-Smoke -Label "fleet-policy-smoke (normalize/filter/cluster/density/uniqueness/aggregate)" -Command { & $python scripts/fleet-policy-smoke.py } -Prereq { $python }
Invoke-Smoke -Label "report-policy-smoke (report QA + expert signoff + visual evidence policy)" -Command { & $python scripts/report-policy-smoke.py } -Prereq { $python }
Invoke-Smoke -Label "readiness-gate-smoke (PacketOnly packaging + fail-closed blockers)" -Command { uv run --directory services/agent python ../../scripts/readiness-gate-smoke.py } -Prereq { (Test-CommandAvailable "uv") -and ((Test-CommandAvailable "powershell") -or (Test-CommandAvailable "pwsh")) }
Invoke-Smoke -Label "launcher-smoke (bash -n + claude binary + no positional .)" -Command {
    if (-not $env:FINDEVIL_LAUNCHER_SMOKE_BASH_TIMEOUT_SECONDS) {
        $env:FINDEVIL_LAUNCHER_SMOKE_BASH_TIMEOUT_SECONDS = "90"
    }
    & $python scripts/launcher-smoke.py
} -Prereq { $python -and (Test-CommandAvailable "bash") }
Invoke-Smoke -Label "divergence-smoke (active divergences downstream-clean)" -Command { & $python scripts/divergence-smoke.py } -Prereq { $python }
Invoke-Smoke -Label "path-existence-smoke (backtick-quoted paths resolve)" -Command { & $python scripts/path-existence-smoke.py } -Prereq { $python }
Invoke-Smoke -Label "trace-finding-smoke (reject post-finalize verdict/manifest tampering)" -Command { & $python scripts/trace-finding-smoke.py } -Prereq { $python }
Invoke-Smoke -Label "install-bootstrap-smoke (--bootstrap gated; default stays fail-closed)" -Command { & $python scripts/install-bootstrap-smoke.py } -Prereq { $python }
Invoke-Smoke -Label "smoke-regex-tests (audit-smoke regex/helper policies)" -Command { & $python scripts/smoke-regex-tests.py } -Prereq { $python }
Invoke-Smoke -Label "render-binary-smoke (pandoc/chrome resolve via PATH, graceful degrade)" -Command { & $python scripts/render-binary-smoke.py } -Prereq { $python }
Invoke-Smoke -Label "starter-data-smoke (SANS_STARTER_URL contract + goldens stub)" -Command { & $python scripts/starter-data-smoke.py } -Prereq { $python }
Invoke-Smoke -Label "golden-answer-key-smoke (all expected-findings schemas valid)" -Command { & $python scripts/golden-answer-key-smoke.py } -Prereq { $python }
Invoke-Smoke -Label "verdict-smoke (the one command, --dry-run)" -Command { & $python scripts/verdict-smoke.py } -Prereq { $python }
Invoke-Smoke -Label "make-demo-video-smoke (TTS+ffmpeg video builder, --dry-run)" -Command { & $python scripts/make-demo-video-smoke.py } -Prereq { $python }
Invoke-Smoke -Label "package-devpost-smoke (submission zip smoke mode)" -Command {
    New-Item -ItemType Directory -Force tmp | Out-Null
    $env:FINDEVIL_DEVPOST_MODE = "smoke"
    $env:RELEASE_TAG = "v-submit-smoke"
    $env:OUT_ZIP = "tmp/package-devpost-smoke.zip"
    $env:RELEASE_ASSETS_DIR = "tmp/package-devpost-assets"
    $env:BENCHMARK_CSV = "tmp/package-devpost-benchmark.csv"
    bash scripts/package-devpost.sh
} -Prereq { Test-CommandAvailable "bash" }
Invoke-Smoke -Label "grounding-smoke (claim extraction + boundary + anti-hallucination contract)" -Command { & $python scripts/grounding-smoke.py } -Prereq { $python -and (Test-Path -LiteralPath "scripts/ground_verdict.py" -PathType Leaf) }

Invoke-Smoke -Label "ruff check . (lint clean across all Python services)" -Command { ruff check . } -Prereq { Test-CommandAvailable "ruff" }
Invoke-Smoke -Label "ruff format --check . (formatter clean)" -Command { ruff format --check . } -Prereq { Test-CommandAvailable "ruff" }
Invoke-Smoke -Label "cargo fmt --all --check (Rust formatter clean)" -Command { cargo fmt --all --check } -Prereq { (Test-CommandAvailable "cargo") -and (Test-Path -LiteralPath "Cargo.toml" -PathType Leaf) }
Invoke-Smoke -Label "cargo clippy --deny warnings (Rust lint clean)" -Command { cargo clippy --workspace --all-targets --locked -- -D warnings } -Prereq { (Test-CommandAvailable "cargo") -and (Test-Path -LiteralPath "Cargo.toml" -PathType Leaf) }

$skipSlow = $SkipSlowRust -or ($env:SKIP_SLOW_RUST -eq "1")
if (-not $skipSlow) {
    Invoke-Smoke -Label "cargo test --workspace --locked (Rust test suite)" -Command { cargo test --workspace --locked } -Prereq { (Test-CommandAvailable "cargo") -and (Test-Path -LiteralPath "Cargo.toml" -PathType Leaf) }
}

$total = $script:passed + $script:failed + $script:skipped
""
"=========================================="
if ($script:failed -eq 0) {
    "OK - $script:passed passed, $script:skipped skipped, 0 failed (of $total)"
    "=========================================="
    exit 0
}

"FAIL - $script:passed passed, $script:skipped skipped, $script:failed failed (of $total)"
"The CI-equivalent gate runs via docker/l1-compose.yml. If a smoke fails"
"locally and passes in Docker/CI, check toolchain versions and Python deps."
"=========================================="
exit 1
