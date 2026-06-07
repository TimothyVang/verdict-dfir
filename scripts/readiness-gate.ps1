# readiness-gate.ps1 - unattended DFIR readiness gate for Windows/OpenCode.
#
# Full mode is the one-command path: local build/smokes, unattended evidence
# run, report packet validation, manifest verification, L1 evidence, and ZIP
# packaging. PacketOnly mode validates/packages an existing run directory for
# fast local testing without claiming full submission readiness.

[CmdletBinding()]
param(
    [ValidateSet("Full", "PacketOnly")]
    [string]$Mode = "Full",

    [string]$EvidencePath = $env:EVIDENCE_PATH,
    [string]$ExistingRunDir = $env:EVIDENCE_RUN_DIR,
    [string]$OutputRoot = $env:READINESS_OUTPUT_ROOT,
    [string]$RunId = $env:READINESS_RUN_ID,

    [ValidateSet("stub", "sigstore")]
    [string]$Signer = $(if ($env:READINESS_SIGNER) { $env:READINESS_SIGNER } else { "stub" }),

    [switch]$ForceFreshReplay,
    [switch]$RunL1Docker,
    [switch]$SkipBuild,
    [switch]$SkipPackage
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $repoRoot

$script:blockers = New-Object System.Collections.Generic.List[string]
$script:warnings = New-Object System.Collections.Generic.List[string]
$script:steps = New-Object System.Collections.Generic.List[object]

function Write-ReadinessLog {
    param([Parameter(Mandatory = $true)][string]$Message)
    [Console]::Error.WriteLine("[readiness-gate] $Message")
}

function Add-ReadinessBlocker {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-ReadinessLog "BLOCKER: $Message"
    $script:blockers.Add($Message) | Out-Null
}

function Add-ReadinessWarning {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-ReadinessLog "WARN: $Message"
    $script:warnings.Add($Message) | Out-Null
}

function Add-ReadinessStep {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Status,
        [string]$Summary = "",
        [string]$Log = "",
        [object]$ExitCode = $null
    )
    $script:steps.Add([ordered]@{
        name = $Name
        status = $Status
        summary = $Summary
        log = $Log
        exit_code = $ExitCode
    }) | Out-Null
}

function Get-EnvString {
    param([Parameter(Mandatory = $true)][string]$Name)
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ($null -eq $value) { return "" }
    return $value
}

function Get-UtcStamp {
    return [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
}

function Get-IsoUtcNow {
    return [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Resolve-LocalPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$MustExist
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return "" }
    $candidate = $Path
    if (-not [System.IO.Path]::IsPathRooted($candidate)) {
        $candidate = Join-Path $repoRoot $candidate
    }
    if ($MustExist) {
        return (Resolve-Path -LiteralPath $candidate).Path
    }
    return [System.IO.Path]::GetFullPath($candidate)
}

function New-DirectoryIfMissing {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Reset-GeneratedDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Container) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
    New-DirectoryIfMissing -Path $Path
}

function New-BuildRunId {
    param([Parameter(Mandatory = $true)][string]$ReadinessRunId)
    $baseRunId = "$ReadinessRunId-build"
    $buildRunRoot = Join-Path $repoRoot "tmp/build-runs"
    $buildState = Join-Path (Join-Path $buildRunRoot $baseRunId) "state.json"
    if (-not (Test-Path -LiteralPath $buildState -PathType Leaf)) {
        return $baseRunId
    }

    $freshRunId = "$baseRunId-$(Get-UtcStamp)"
    Add-ReadinessWarning "local build run already exists for $baseRunId; using fresh build run id $freshRunId"
    return $freshRunId
}

function Get-PythonCommand {
    foreach ($candidate in @("python", "python3")) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($null -ne $command) { return $command.Source }
    }
    Add-ReadinessBlocker "python/python3 not found"
    return "python"
}

function ConvertTo-CommandText {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @()
    )
    $parts = @($Command) + $Arguments
    return ($parts | ForEach-Object {
        $part = [string]$_
        if ($part -match '[\s"`$]') {
            '"' + ($part -replace '"', '\"') + '"'
        }
        else {
            $part
        }
    }) -join " "
}

function Invoke-LoggedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @()
    )
    $safeName = ($Name -replace '[^A-Za-z0-9_.-]', '-')
    $logPath = Join-Path $script:logsDir "$safeName.log"
    $commandText = ConvertTo-CommandText -Command $Command -Arguments $Arguments
    Write-ReadinessLog "running: $Name"
    Write-ReadinessLog "command: $commandText"
    $global:LASTEXITCODE = 0
    $output = @()
    try {
        $output = & $Command @Arguments 2>&1
        $exitCode = $global:LASTEXITCODE
        if ($null -eq $exitCode) { $exitCode = if ($?) { 0 } else { 1 } }
    }
    catch {
        $output = @($_.Exception.Message)
        $exitCode = 1
    }
    [System.IO.File]::WriteAllLines($logPath, [string[]](@("# $commandText") + $output))
    $status = if ($exitCode -eq 0) { "passed" } else { "failed" }
    Add-ReadinessStep -Name $Name -Status $status -Summary $commandText -Log $logPath -ExitCode $exitCode
    if ($exitCode -ne 0) {
        Add-ReadinessBlocker "$Name failed; see $logPath"
    }
    else {
        Write-ReadinessLog "PASS: $Name"
    }
    return [ordered]@{
        exit_code = $exitCode
        log = $logPath
        output = [string[]]$output
    }
}

function Invoke-L1DockerGate {
    $name = "l1-docker"
    $safeName = ($name -replace '[^A-Za-z0-9_.-]', '-')
    $logPath = Join-Path $script:logsDir "$safeName.log"
    $arguments = @("compose", "--progress", "plain", "-f", "docker/l1-compose.yml", "up", "--build", "--exit-code-from", "l1")
    $commandText = ConvertTo-CommandText -Command "docker" -Arguments $arguments
    $startedBefore = [DateTime]::UtcNow.AddSeconds(-5)
    Write-ReadinessLog "running: $name"
    Write-ReadinessLog "command: $commandText"

    $global:LASTEXITCODE = 0
    $output = @()
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = & docker @arguments 2>&1
        $exitCode = $global:LASTEXITCODE
        if ($null -eq $exitCode) { $exitCode = if ($?) { 0 } else { 1 } }
    }
    catch {
        $output = @($_.Exception.Message)
        $exitCode = 1
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# $commandText") | Out-Null
    foreach ($line in [string[]]$output) { $lines.Add($line) | Out-Null }

    $markerPresent = (($output -join "`n") -match "READINESS_L1_PASS")
    $containerExitCode = $null
    $containerStartedOk = $false
    $containerOomKilled = $false

    try {
        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $inspect = & docker inspect --format "{{.State.Status}}|{{.State.ExitCode}}|{{.State.OOMKilled}}|{{.State.StartedAt}}" findevil-l1 2>&1
        $inspectNativeExit = $global:LASTEXITCODE
        $ErrorActionPreference = $previousErrorActionPreference
        if ($inspectNativeExit -eq 0 -and $inspect) {
            $parts = ([string]$inspect).Split("|")
            if ($parts.Count -ge 4) {
                $status = $parts[0]
                $containerExitCode = [int]$parts[1]
                $containerOomKilled = ([string]$parts[2]) -eq "true"
                try {
                    $containerStarted = [DateTime]::Parse([string]$parts[3]).ToUniversalTime()
                    $containerStartedOk = $containerStarted -ge $startedBefore
                }
                catch {
                    $containerStartedOk = $false
                }
                $lines.Add("# findevil-l1 inspect: $inspect") | Out-Null
                if ($status -eq "running" -and $containerStartedOk) {
                    $previousErrorActionPreference = $ErrorActionPreference
                    $ErrorActionPreference = "Continue"
                    $waitOutput = & docker wait findevil-l1 2>&1
                    $waitExit = $global:LASTEXITCODE
                    $ErrorActionPreference = $previousErrorActionPreference
                    foreach ($line in [string[]]$waitOutput) { $lines.Add("# docker wait: $line") | Out-Null }
                    if ($waitExit -eq 0 -and $waitOutput) {
                        $lastWaitLine = ([string[]]$waitOutput)[-1]
                        $parsedWait = 0
                        if ([int]::TryParse($lastWaitLine, [ref]$parsedWait)) {
                            $containerExitCode = $parsedWait
                        }
                    }
                }
            }
        }
        else {
            foreach ($line in [string[]]$inspect) { $lines.Add("# docker inspect failed: $line") | Out-Null }
        }
    }
    catch {
        $ErrorActionPreference = $previousErrorActionPreference
        $lines.Add("# docker inspect exception: $($_.Exception.Message)") | Out-Null
    }

    try {
        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $dockerLogs = & docker logs findevil-l1 2>&1
        $ErrorActionPreference = $previousErrorActionPreference
        foreach ($line in [string[]]$dockerLogs) { $lines.Add($line) | Out-Null }
        if (($dockerLogs -join "`n") -match "READINESS_L1_PASS") { $markerPresent = $true }
    }
    catch {
        $ErrorActionPreference = $previousErrorActionPreference
        $lines.Add("# docker logs exception: $($_.Exception.Message)") | Out-Null
    }

    [System.IO.File]::WriteAllLines($logPath, [string[]]$lines)

    $passed = $markerPresent -and ($exitCode -eq 0 -or ($containerStartedOk -and $containerExitCode -eq 0 -and -not $containerOomKilled))
    if ($passed) {
        Add-ReadinessStep -Name $name -Status "passed" -Summary $commandText -Log $logPath -ExitCode 0
        Write-ReadinessLog "PASS: $name"
    }
    else {
        Add-ReadinessStep -Name $name -Status "failed" -Summary $commandText -Log $logPath -ExitCode $exitCode
        Add-ReadinessBlocker "$name failed; see $logPath"
    }
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
    }
    catch {
        Add-ReadinessBlocker "invalid JSON at ${Path}: $($_.Exception.Message)"
        return $null
    }
}

function Get-JsonPropertyValue {
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-FirstJsonString {
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string[]]$Names
    )
    foreach ($name in $Names) {
        $value = Get-JsonPropertyValue -Object $Object -Name $name
        if ($value -is [string] -and -not [string]::IsNullOrWhiteSpace($value)) {
            return [string]$value
        }
    }
    return ""
}

function Read-FindEvilAutoRunSummary {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-ReadinessBlocker "find-evil-auto run summary missing: $Path"
        return $null
    }
    try {
        $summary = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        Add-ReadinessBlocker "find-evil-auto run summary is malformed JSON: ${Path}: $($_.Exception.Message)"
        return $null
    }
    if ($null -eq $summary -or $summary -is [array]) {
        Add-ReadinessBlocker "find-evil-auto run summary must be a JSON object: $Path"
        return $null
    }
    return $summary
}

function Resolve-FindEvilAutoRunDir {
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Summary,
        [Parameter(Mandatory = $true)][string]$SummaryPath
    )
    if ($null -eq $Summary) { return "" }
    $candidate = Get-FirstJsonString -Object $Summary -Names @(
        "local_dir",
        "run_dir",
        "completed_run_dir",
        "evidence_run_dir",
        "output_dir"
    )
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $artifacts = Get-JsonPropertyValue -Object $Summary -Name "artifacts"
        $candidate = Get-FirstJsonString -Object $artifacts -Names @(
            "local_dir",
            "run_dir",
            "completed_run_dir",
            "evidence_run_dir",
            "output_dir"
        )
    }
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        Add-ReadinessBlocker "find-evil-auto run summary lacks completed run directory field (expected local_dir/run_dir/evidence_run_dir): $SummaryPath"
        return ""
    }
    $resolved = Resolve-LocalPath -Path $candidate
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        Add-ReadinessBlocker "find-evil-auto run summary points to missing run directory: $candidate ($resolved)"
        return ""
    }
    return (Resolve-Path -LiteralPath $resolved).Path
}

function Resolve-RunArtifactPath {
    param(
        [Parameter(Mandatory = $true)][string]$RunDir,
        [Parameter(Mandatory = $true)][AllowNull()]$Summary,
        [Parameter(Mandatory = $true)][string[]]$Names,
        [Parameter(Mandatory = $true)][string]$DefaultName
    )
    $candidate = Get-FirstJsonString -Object $Summary -Names $Names
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $artifacts = Get-JsonPropertyValue -Object $Summary -Name "artifacts"
        $candidate = Get-FirstJsonString -Object $artifacts -Names $Names
    }
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $paths = Get-JsonPropertyValue -Object $Summary -Name "paths"
        $candidate = Get-FirstJsonString -Object $paths -Names $Names
    }
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        return (Join-Path $RunDir $DefaultName)
    }
    if (-not [System.IO.Path]::IsPathRooted($candidate)) {
        $candidate = Join-Path $RunDir $candidate
    }
    return [System.IO.Path]::GetFullPath($candidate)
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )
    $json = $Value | ConvertTo-Json -Depth 20
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, $utf8NoBom)
}

function Test-AuditKind {
    param(
        [Parameter(Mandatory = $true)][object[]]$AuditKinds,
        [Parameter(Mandatory = $true)][string]$Kind
    )
    return ($AuditKinds -contains $Kind)
}

function Read-AuditKinds {
    param([Parameter(Mandatory = $true)][string]$AuditPath)
    $kinds = New-Object System.Collections.Generic.List[string]
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $AuditPath -Encoding UTF8) {
        $lineNumber += 1
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $record = $line | ConvertFrom-Json
        }
        catch {
            Add-ReadinessBlocker "audit log line $lineNumber is not valid JSON: $AuditPath"
            continue
        }
        if ($null -eq $record.kind -or [string]::IsNullOrWhiteSpace([string]$record.kind)) {
            Add-ReadinessBlocker "audit log line $lineNumber lacks top-level kind: $AuditPath"
            continue
        }
        $kinds.Add([string]$record.kind) | Out-Null
    }
    return $kinds.ToArray()
}

function Invoke-ManifestVerify {
    param(
        [Parameter(Mandatory = $true)][string]$RunDir,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$AuditPath,
        [Parameter(Mandatory = $true)][string]$PythonBin
    )
    $verifyPath = Join-Path $RunDir "manifest_verify.json"
    $uv = Get-Command "uv" -ErrorAction SilentlyContinue
    if ($null -eq $uv) {
        Add-ReadinessBlocker "uv is unavailable; cannot recompute manifest verification"
        return $verifyPath
    }
    $code = "import dataclasses, json, sys; from pathlib import Path; from findevil_agent.crypto.manifest import verify_manifest; result = verify_manifest(Path(sys.argv[1]), audit_log_path=Path(sys.argv[2])); Path(sys.argv[3]).write_text(json.dumps(dataclasses.asdict(result), indent=2, sort_keys=True), encoding='utf-8')"
    $result = Invoke-LoggedCommand -Name "manifest-verify-local" -Command $uv.Source -Arguments @(
        "run", "--directory", "services/agent", "python", "-c", $code,
        $ManifestPath, $AuditPath, $verifyPath
    )
    if ($result.exit_code -ne 0) {
        Add-ReadinessBlocker "manifest verification fallback failed"
    }
    return $verifyPath
}

function Invoke-RenderReportIfNeeded {
    param(
        [Parameter(Mandatory = $true)][string]$RunDir,
        [Parameter(Mandatory = $true)][string]$PythonBin
    )
    $htmlPath = Join-Path $RunDir "REPORT.html"
    $pdfPath = Join-Path $RunDir "REPORT.pdf"
    if ((Test-Path -LiteralPath $htmlPath -PathType Leaf) -or (Test-Path -LiteralPath $pdfPath -PathType Leaf)) {
        return
    }
    if ((Test-Path -LiteralPath (Join-Path $RunDir "run.manifest.json") -PathType Leaf) -and
        (Test-Path -LiteralPath (Join-Path $RunDir "verdict.json") -PathType Leaf)) {
        $result = Invoke-LoggedCommand -Name "render-report" -Command $PythonBin -Arguments @("scripts/render_report.py", $RunDir)
        if ($result.exit_code -ne 0) {
            Add-ReadinessBlocker "report render failed for $RunDir"
        }
    }
}

function Copy-PacketFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [switch]$Required
    )
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        if ($Required) { Add-ReadinessBlocker "packet artifact missing: $RelativePath ($Source)" }
        return
    }
    $destination = Join-Path $script:packetDir $RelativePath
    New-DirectoryIfMissing -Path (Split-Path -Parent $destination)
    Copy-Item -LiteralPath $Source -Destination $destination -Force
}

function Copy-PacketDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )
    if (-not (Test-Path -LiteralPath $Source -PathType Container)) { return }
    $destination = Join-Path $script:packetDir $RelativePath
    if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Recurse -Force }
    New-DirectoryIfMissing -Path (Split-Path -Parent $destination)
    Copy-Item -LiteralPath $Source -Destination $destination -Recurse -Force
}

function New-PacketManifest {
    param(
        [Parameter(Mandatory = $true)][string]$PacketDir,
        [string]$RunDir = "",
        [Parameter(Mandatory = $true)][string]$ReadinessState
    )
    $root = (Resolve-Path -LiteralPath $PacketDir).Path
    $artifacts = @()
    foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File | Sort-Object FullName) {
        if ($file.Name -eq "readiness-packet-manifest.json") { continue }
        $relative = $file.FullName.Substring($root.Length).TrimStart([char[]]@('\', '/'))
        $artifacts += [ordered]@{
            path = ($relative -replace '\\', '/')
            size_bytes = $file.Length
            sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        }
    }
    $manifest = [ordered]@{
        version = 1
        generated_at = Get-IsoUtcNow
        readiness_state = $ReadinessState
        source_run_dir = $RunDir
        artifact_count = $artifacts.Count
        artifacts = $artifacts
    }
    $path = Join-Path $PacketDir "readiness-packet-manifest.json"
    Write-JsonFile -Path $path -Value $manifest
    return $path
}

function New-PacketZip {
    param(
        [Parameter(Mandatory = $true)][string]$PacketDir,
        [Parameter(Mandatory = $true)][string]$ZipPath
    )
    if ($SkipPackage) {
        Add-ReadinessWarning "packet ZIP creation skipped by -SkipPackage"
        Add-ReadinessStep -Name "packet-zip" -Status "skipped" -Summary "-SkipPackage was set"
        return
    }
    try {
        if (Test-Path -LiteralPath $ZipPath -PathType Leaf) {
            Remove-Item -LiteralPath $ZipPath -Force
        }
        Compress-Archive -Path (Join-Path $PacketDir "*") -DestinationPath $ZipPath -Force
        Add-ReadinessStep -Name "packet-zip" -Status "passed" -Summary $ZipPath
        Write-ReadinessLog "PASS: packet ZIP created ($ZipPath)"
    }
    catch {
        Add-ReadinessBlocker "packet ZIP creation failed: $($_.Exception.Message)"
        Add-ReadinessStep -Name "packet-zip" -Status "failed" -Summary $_.Exception.Message
    }
}

function Invoke-SubmissionAssetsValidator {
    param(
        [Parameter(Mandatory = $true)][string]$SummaryPath,
        [Parameter(Mandatory = $true)][string]$PythonBin
    )
    $result = Invoke-LoggedCommand -Name "submission-assets-validator" -Command $PythonBin -Arguments @(
        "scripts/validate-submission-assets.py", "--readiness-summary", $SummaryPath
    )
    if ($null -ne $result.log -and (Test-Path -LiteralPath $result.log -PathType Leaf)) {
        Copy-PacketFile -Source $result.log -RelativePath "logs/submission-assets-validator.log"
    }
    return $result
}

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot "tmp/readiness-gates"
}
else {
    $OutputRoot = Resolve-LocalPath -Path $OutputRoot
}
if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = "readiness-$(Get-UtcStamp)"
}
if ($RunId -notmatch '^[A-Za-z0-9_.-]+$') {
    throw "RunId must contain only letters, numbers, dot, underscore, and dash: $RunId"
}

$runRoot = Join-Path $OutputRoot $RunId
$script:logsDir = Join-Path $runRoot "logs"
$script:packetDir = Join-Path $runRoot "packet"
New-DirectoryIfMissing -Path $script:logsDir
Reset-GeneratedDirectory -Path $script:packetDir

$pythonBin = Get-PythonCommand
$resolvedRunDir = ""
$findEvilAutoRunSummary = $null

Write-ReadinessLog "mode: $Mode"
Write-ReadinessLog "run: $runRoot"

if ($Mode -eq "Full") {
    if ($SkipBuild) {
        Add-ReadinessBlocker "local build was skipped; Full readiness requires scripts/build-checker.py run"
        Add-ReadinessStep -Name "local-build" -Status "skipped" -Summary "-SkipBuild was set"
    }
    else {
        $buildRunId = if (Get-EnvString "BUILD_RUN_ID") { Get-EnvString "BUILD_RUN_ID" } else { New-BuildRunId -ReadinessRunId $RunId }
        Invoke-LoggedCommand -Name "local-build" -Command $pythonBin -Arguments @("scripts/build-checker.py", "run", "--run-id", $buildRunId) | Out-Null
    }
}

if (-not [string]::IsNullOrWhiteSpace($ExistingRunDir)) {
    try {
        $resolvedRunDir = Resolve-LocalPath -Path $ExistingRunDir -MustExist
        Write-ReadinessLog "using existing evidence run: $resolvedRunDir"
    }
    catch {
        Add-ReadinessBlocker "ExistingRunDir does not exist: $ExistingRunDir"
    }
}
elseif ($Mode -eq "Full" -and -not [string]::IsNullOrWhiteSpace($EvidencePath)) {
    $autoRunSummaryPath = Join-Path $script:logsDir "find-evil-auto-run-summary.json"
    $autoArgs = @("scripts/find_evil_auto.py", $EvidencePath, "--unattended", "--signer", $Signer, "--run-summary", $autoRunSummaryPath)
    if ($ForceFreshReplay) { $autoArgs += "--force-fresh-replay" }
    Invoke-LoggedCommand -Name "find-evil-auto" -Command $pythonBin -Arguments $autoArgs | Out-Null
    $findEvilAutoRunSummary = Read-FindEvilAutoRunSummary -Path $autoRunSummaryPath
    $resolvedRunDir = Resolve-FindEvilAutoRunDir -Summary $findEvilAutoRunSummary -SummaryPath $autoRunSummaryPath
    if (-not [string]::IsNullOrWhiteSpace($resolvedRunDir)) {
        Write-ReadinessLog "evidence run: $resolvedRunDir"
    }
}
elseif ($Mode -eq "Full") {
    Add-ReadinessBlocker "EvidencePath missing; pass -EvidencePath or set EVIDENCE_PATH, or use -ExistingRunDir for an already completed run"
}
elseif ($Mode -eq "PacketOnly") {
    Add-ReadinessBlocker "PacketOnly mode requires -ExistingRunDir or EVIDENCE_RUN_DIR"
}

if ($Mode -eq "Full") {
    $shouldRunL1 = $RunL1Docker.IsPresent -or ((Get-EnvString "RUN_L1_DOCKER") -eq "1")
    if ($shouldRunL1) {
        Invoke-L1DockerGate
    }
    elseif ((Get-EnvString "L1_DOCKER_STATUS") -eq "passed") {
        $l1DockerLog = Get-EnvString "L1_DOCKER_LOG"
        if ($l1DockerLog -ne "") {
            $l1DockerLog = Resolve-LocalPath -Path $l1DockerLog
        }
        if ($l1DockerLog -ne "" -and (Test-Path -LiteralPath $l1DockerLog -PathType Leaf)) {
            $hasMarker = Select-String -LiteralPath $l1DockerLog -Pattern "READINESS_L1_PASS" -SimpleMatch -Quiet
            if ($hasMarker) {
                Add-ReadinessStep -Name "l1-docker" -Status "passed" -Summary "evidence marker present" -Log $l1DockerLog
                Write-ReadinessLog "PASS: L1 Docker evidence marker present ($l1DockerLog)"
            }
            else {
                Add-ReadinessBlocker "L1_DOCKER_LOG must contain exact marker READINESS_L1_PASS: $l1DockerLog"
            }
        }
        else {
            Add-ReadinessBlocker "L1_DOCKER_STATUS=passed requires L1_DOCKER_LOG pointing to evidence"
        }
    }
    else {
        Add-ReadinessBlocker "L1 Docker evidence missing; run with -RunL1Docker/RUN_L1_DOCKER=1 or set L1_DOCKER_STATUS=passed plus L1_DOCKER_LOG containing READINESS_L1_PASS"
    }
}

$manifestPath = ""
$auditPath = ""
$verdictPath = ""
$manifestVerifyPath = ""
$reportHtmlPath = ""
$reportPdfPath = ""
$reportMdPath = ""
$expertSignoffPath = ""
$releaseGatePath = ""
$readinessState = "READINESS_BLOCKED"

if (-not [string]::IsNullOrWhiteSpace($resolvedRunDir)) {
    if ($resolvedRunDir -like "*smoke*") {
        Add-ReadinessBlocker "evidence run directory looks like a smoke run: $resolvedRunDir"
    }

    $manifestPath = Resolve-RunArtifactPath -RunDir $resolvedRunDir -Summary $findEvilAutoRunSummary -Names @("run_manifest", "manifest", "manifest_path", "run_manifest_path") -DefaultName "run.manifest.json"
    $auditPath = Resolve-RunArtifactPath -RunDir $resolvedRunDir -Summary $findEvilAutoRunSummary -Names @("audit_log", "audit", "audit_path", "audit_log_path") -DefaultName "audit.jsonl"
    $verdictPath = Resolve-RunArtifactPath -RunDir $resolvedRunDir -Summary $findEvilAutoRunSummary -Names @("verdict", "verdict_path") -DefaultName "verdict.json"
    $expertSignoffPath = Resolve-RunArtifactPath -RunDir $resolvedRunDir -Summary $findEvilAutoRunSummary -Names @("expert_signoff", "expert_signoff_path") -DefaultName "expert_signoff.json"
    $releaseGatePath = Resolve-RunArtifactPath -RunDir $resolvedRunDir -Summary $findEvilAutoRunSummary -Names @("customer_release_gate", "customer_release_gate_final", "release_gate", "release_gate_path") -DefaultName "customer_release_gate.final.json"
    foreach ($required in @(
        @($manifestPath, "run.manifest.json"),
        @($auditPath, "audit.jsonl"),
        @($verdictPath, "verdict.json"),
        @($expertSignoffPath, "expert_signoff.json"),
        @($releaseGatePath, "customer_release_gate.final.json")
    )) {
        if (-not (Test-Path -LiteralPath $required[0] -PathType Leaf)) {
            Add-ReadinessBlocker "evidence run missing $($required[1]): $($required[0])"
        }
    }

    if (Test-Path -LiteralPath $auditPath -PathType Leaf) {
        $auditKinds = Read-AuditKinds -AuditPath $auditPath
        foreach ($kind in @("report_qa", "customer_release_gate", "verdict_artifact", "expert_signoff_packet")) {
            if (-not (Test-AuditKind -AuditKinds $auditKinds -Kind $kind)) {
                Add-ReadinessBlocker "audit log lacks required $kind record: $auditPath"
            }
        }
    }

    if ((Test-Path -LiteralPath $manifestPath -PathType Leaf) -and (Test-Path -LiteralPath $auditPath -PathType Leaf)) {
        $manifestVerifyPath = Invoke-ManifestVerify -RunDir $resolvedRunDir -ManifestPath $manifestPath -AuditPath $auditPath -PythonBin $pythonBin
    }

    Invoke-RenderReportIfNeeded -RunDir $resolvedRunDir -PythonBin $pythonBin
    $reportHtmlPath = Join-Path $resolvedRunDir "REPORT.html"
    $reportPdfPath = Join-Path $resolvedRunDir "REPORT.pdf"
    $reportMdPath = Join-Path $resolvedRunDir "REPORT.md"
    if (-not ((Test-Path -LiteralPath $reportHtmlPath -PathType Leaf) -or (Test-Path -LiteralPath $reportPdfPath -PathType Leaf))) {
        Add-ReadinessBlocker "no report artifact found; expected REPORT.html or REPORT.pdf in $resolvedRunDir"
    }
    elseif (-not (Test-Path -LiteralPath $reportPdfPath -PathType Leaf)) {
        Add-ReadinessWarning "REPORT.pdf missing; packet contains HTML report only"
    }

    $verdictObj = $null
    if (Test-Path -LiteralPath $verdictPath -PathType Leaf) {
        $verdictObj = Read-JsonFile -Path $verdictPath
    }
    $manifestVerifyObj = $null
    if (Test-Path -LiteralPath $manifestVerifyPath -PathType Leaf) {
        $manifestVerifyObj = Read-JsonFile -Path $manifestVerifyPath
    }
    else {
        Add-ReadinessBlocker "manifest_verify.json missing after verification step: $manifestVerifyPath"
    }

    if ($null -ne $manifestVerifyObj -and -not [bool]$manifestVerifyObj.overall) {
        Add-ReadinessBlocker "manifest_verify overall=false for $manifestVerifyPath"
    }

    if ($null -ne $verdictObj) {
        $reportQa = $verdictObj.report_qa
        if ($null -eq $reportQa) {
            Add-ReadinessBlocker "verdict.json lacks report_qa"
        }
        else {
            if ($reportQa.status -eq "FAIL" -or $reportQa.status -notin @("PASS", "WARN")) {
                Add-ReadinessBlocker "report QA is not ready for expert review: status=$($reportQa.status) packet_state=$($reportQa.packet_state)"
            }
            elseif ($reportQa.status -eq "WARN") {
                Add-ReadinessWarning "report QA has warnings: $($reportQa.packet_state)"
            }
            if (-not [bool]$reportQa.ready_for_expert_signoff) {
                Add-ReadinessBlocker "report QA does not mark packet ready_for_expert_signoff"
            }
            if ([bool]$reportQa.customer_releasable) {
                Add-ReadinessBlocker "report_qa marks customer_releasable; readiness gate stops at expert review"
            }
        }
        $releaseGate = $verdictObj.release_gate
        if ($null -ne $releaseGate -and [bool]$releaseGate.customer_releasable) {
            Add-ReadinessBlocker "automated gate must not mark customer_releasable without explicit human expert approval"
        }
        $expertSignoff = $verdictObj.expert_signoff
        if ($null -ne $expertSignoff -and [bool]$expertSignoff.customer_releasable) {
            Add-ReadinessBlocker "expert_signoff in verdict marks customer_releasable; readiness gate stops at expert review"
        }
    }
    if (Test-Path -LiteralPath $releaseGatePath -PathType Leaf) {
        $releaseGateObj = Read-JsonFile -Path $releaseGatePath
        if ($null -ne $releaseGateObj -and [bool]$releaseGateObj.customer_releasable) {
            Add-ReadinessBlocker "customer_release_gate.final.json marks customer_releasable; readiness gate stops at expert review"
        }
    }
    if (Test-Path -LiteralPath $expertSignoffPath -PathType Leaf) {
        $expertSignoffObj = Read-JsonFile -Path $expertSignoffPath
        if ($null -ne $expertSignoffObj -and [bool]$expertSignoffObj.customer_releasable) {
            Add-ReadinessBlocker "expert_signoff.json marks customer_releasable; readiness gate stops at expert review"
        }
    }

    Copy-PacketFile -Source $auditPath -RelativePath "audit.jsonl" -Required
    Copy-PacketFile -Source $manifestPath -RelativePath "run.manifest.json" -Required
    Copy-PacketFile -Source $manifestVerifyPath -RelativePath "manifest_verify.json" -Required
    Copy-PacketFile -Source $verdictPath -RelativePath "verdict.json" -Required
    Copy-PacketFile -Source $expertSignoffPath -RelativePath "expert_signoff.json" -Required
    Copy-PacketFile -Source $releaseGatePath -RelativePath "customer_release_gate.final.json" -Required
    Copy-PacketFile -Source (Join-Path $resolvedRunDir "expert_signoff_manifest_link.json") -RelativePath "expert_signoff_manifest_link.json"
    Copy-PacketFile -Source (Join-Path $resolvedRunDir "evidence_inventory.json") -RelativePath "evidence_inventory.json"
    Copy-PacketFile -Source (Join-Path $resolvedRunDir "malware_triage.json") -RelativePath "malware_triage.json"
    Copy-PacketFile -Source (Join-Path $resolvedRunDir "timeline.json") -RelativePath "timeline.json"
    Copy-PacketFile -Source (Join-Path $resolvedRunDir "timeline.csv") -RelativePath "timeline.csv"
    Copy-PacketFile -Source $reportMdPath -RelativePath "REPORT.md"
    Copy-PacketFile -Source $reportHtmlPath -RelativePath "REPORT.html"
    Copy-PacketFile -Source $reportPdfPath -RelativePath "REPORT.pdf"
    Copy-PacketDirectory -Source (Join-Path $resolvedRunDir "figures") -RelativePath "figures"
}

if ($script:blockers.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($resolvedRunDir)) {
    $readinessState = if ($Mode -eq "Full") { "READY_FOR_EXPERT_REVIEW" } else { "PACKET_READY_FOR_EXPERT_REVIEW" }
}

$packetManifestPath = New-PacketManifest -PacketDir $script:packetDir -RunDir $resolvedRunDir -ReadinessState $readinessState
$packetZip = Join-Path $runRoot "readiness-packet.zip"
New-PacketZip -PacketDir $script:packetDir -ZipPath $packetZip

if ($script:blockers.Count -eq 0 -and -not (Test-Path -LiteralPath $packetZip -PathType Leaf) -and -not $SkipPackage) {
    Add-ReadinessBlocker "readiness packet ZIP missing: $packetZip"
    $readinessState = "READINESS_BLOCKED"
}
if ($script:blockers.Count -ne 0) {
    $readinessState = "READINESS_BLOCKED"
}

$summary = [ordered]@{
    version = 1
    generated_at = Get-IsoUtcNow
    mode = $Mode
    run_id = $RunId
    readiness_state = $readinessState
    repo_root = $repoRoot
    evidence_path = $EvidencePath
    evidence_run_dir = $resolvedRunDir
    packet_dir = $script:packetDir
    packet_manifest = $packetManifestPath
    packet_zip = if (Test-Path -LiteralPath $packetZip -PathType Leaf) { $packetZip } else { $null }
    signer = $Signer
    customer_releasable = $false
    expert_release_gate = "human expert approval remains required before customer release"
    blockers = $script:blockers.ToArray()
    warnings = $script:warnings.ToArray()
    steps = $script:steps.ToArray()
}
$summaryPath = Join-Path $runRoot "readiness-summary.json"
Write-JsonFile -Path $summaryPath -Value $summary
Copy-PacketFile -Source $summaryPath -RelativePath "readiness-summary.json" -Required
$packetManifestPath = New-PacketManifest -PacketDir $script:packetDir -RunDir $resolvedRunDir -ReadinessState $readinessState
if (-not $SkipPackage -and (Test-Path -LiteralPath $packetZip -PathType Leaf)) {
    try {
        Compress-Archive -Path (Join-Path $script:packetDir "*") -DestinationPath $packetZip -Force
    }
    catch {
        Add-ReadinessBlocker "final packet ZIP refresh failed: $($_.Exception.Message)"
    }
}

Invoke-SubmissionAssetsValidator -SummaryPath $summaryPath -PythonBin $pythonBin | Out-Null

if ($script:blockers.Count -ne @($summary["blockers"]).Count -or $script:steps.Count -ne @($summary["steps"]).Count -or $script:warnings.Count -ne @($summary["warnings"]).Count) {
    if ($script:blockers.Count -ne 0) {
        $readinessState = "READINESS_BLOCKED"
    }
    $summary["readiness_state"] = $readinessState
    $summary["blockers"] = $script:blockers.ToArray()
    $summary["warnings"] = $script:warnings.ToArray()
    $summary["steps"] = $script:steps.ToArray()
    Write-JsonFile -Path $summaryPath -Value $summary
    Copy-PacketFile -Source $summaryPath -RelativePath "readiness-summary.json" -Required
    $packetManifestPath = New-PacketManifest -PacketDir $script:packetDir -RunDir $resolvedRunDir -ReadinessState $readinessState
    if (-not $SkipPackage -and (Test-Path -LiteralPath $packetZip -PathType Leaf)) {
        try {
            Compress-Archive -Path (Join-Path $script:packetDir "*") -DestinationPath $packetZip -Force
        }
        catch {
            Add-ReadinessBlocker "post-validator packet ZIP refresh failed: $($_.Exception.Message)"
            $readinessState = "READINESS_BLOCKED"
            $summary["readiness_state"] = $readinessState
            $summary["blockers"] = $script:blockers.ToArray()
            $summary["warnings"] = $script:warnings.ToArray()
            $summary["steps"] = $script:steps.ToArray()
            Write-JsonFile -Path $summaryPath -Value $summary
            Copy-PacketFile -Source $summaryPath -RelativePath "readiness-summary.json" -Required
        }
    }
}

Write-ReadinessLog "summary: $summaryPath"
Write-ReadinessLog "packet: $script:packetDir"

if ($script:blockers.Count -eq 0 -and $readinessState -ne "READINESS_BLOCKED") {
    Write-ReadinessLog $readinessState
    exit 0
}

Write-ReadinessLog "READINESS_BLOCKED ($($script:blockers.Count) blocker(s))"
exit 1
