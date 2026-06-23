[CmdletBinding()]
param(
    [string]$ReadinessDir = $env:COVENANT_RELEASE_READINESS_DIR,

    [string]$Version = $env:COVENANT_RELEASE_VERSION,

    [string]$Commit = $env:COVENANT_RELEASE_COMMIT,

    [string]$Date = $env:COVENANT_RELEASE_DATE,

    [string]$Target = $env:COVENANT_RELEASE_TARGET
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Show-Usage {
    @"
Usage: .\release-readiness.ps1 [-ReadinessDir dir] [-Version version] [-Commit commit] [-Date utc-date] [-Target os/arch]

Runs the Windows-native AO Covenant release-readiness smoke gate and writes a
schema-backed release-readiness-summary.json artifact. The generated workspace
contains private signing material and local paths; upload only the summary.

Do not paste private keys, credentials, production evidence bundles, unreleased
bundles, or local machine paths into public issues when reporting failures.
"@
}

function Fail {
    param([string]$Message)
    Write-Error "release readiness: $Message"
    exit 1
}

function Join-ChildPath {
    param(
        [string]$Base,
        [string[]]$Children
    )
    $Path = $Base
    foreach ($Child in $Children) {
        $Path = Join-Path $Path $Child
    }
    return $Path
}

function Write-Utf8NoBom {
    param(
        [string]$Path,
        [string]$Content
    )
    $Encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $Encoding)
}

function Invoke-Native {
    param(
        [string]$Command,
        [string[]]$Arguments,
        [string]$WorkingDirectory = ""
    )
    $OriginalLocation = (Get-Location).Path
    try {
        if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
            Set-Location -LiteralPath $WorkingDirectory
        }
        & $Command @Arguments
        $ExitCode = $LASTEXITCODE
    }
    finally {
        Set-Location -LiteralPath $OriginalLocation
    }
    if ($ExitCode -ne 0) {
        Fail "command failed with exit code ${ExitCode}: $Command $($Arguments -join ' ')"
    }
}

function Invoke-NativeToFile {
    param(
        [string]$Command,
        [string[]]$Arguments,
        [string]$OutputPath,
        [string]$WorkingDirectory = ""
    )
    $OriginalLocation = (Get-Location).Path
    try {
        if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
            Set-Location -LiteralPath $WorkingDirectory
        }
        $Output = & $Command @Arguments
        $ExitCode = $LASTEXITCODE
    }
    finally {
        Set-Location -LiteralPath $OriginalLocation
    }
    Write-Utf8NoBom -Path $OutputPath -Content (($Output -join [Environment]::NewLine) + [Environment]::NewLine)
    if ($ExitCode -ne 0) {
        Fail "command failed with exit code ${ExitCode}: $Command $($Arguments -join ' ')"
    }
}

function Invoke-CovenantToFile {
    param(
        [string[]]$Arguments,
        [string]$OutputPath
    )
    Invoke-NativeToFile -Command $Bin -Arguments $Arguments -OutputPath $OutputPath -WorkingDirectory $Workspace
}

function Save-Json {
    param(
        [string]$Name,
        [string[]]$Arguments
    )
    Invoke-CovenantToFile -Arguments $Arguments -OutputPath (Join-ChildPath $Artifacts @("$Name.json"))
}

$Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$HostOS = (& go env GOOS).Trim()
$HostArch = (& go env GOARCH).Trim()

if ([string]::IsNullOrWhiteSpace($ReadinessDir)) {
    $ReadinessDir = Join-ChildPath $Root @(".covenant", "release-readiness")
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = "v0.1.0-readiness"
}
if ([string]::IsNullOrWhiteSpace($Commit)) {
    $GitCommit = & git -C $Root rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($GitCommit)) {
        $Commit = $GitCommit.Trim()
    }
    else {
        $Commit = "unknown"
    }
}
if ([string]::IsNullOrWhiteSpace($Date)) {
    $Date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}
if ([string]::IsNullOrWhiteSpace($Target)) {
    $Target = "$HostOS/$HostArch"
}

$Workspace = $ReadinessDir
$Artifacts = Join-ChildPath $ReadinessDir @("artifacts")
$Dist = Join-ChildPath $ReadinessDir @("release")
$BinDir = Join-ChildPath $ReadinessDir @("bin")
$Bin = Join-ChildPath $BinDir @("covenant")
if ($HostOS -eq "windows") {
    $Bin = "$Bin.exe"
}
$Summary = Join-ChildPath $ReadinessDir @("release-readiness-summary.json")

if (Test-Path -LiteralPath $ReadinessDir) {
    Remove-Item -LiteralPath $ReadinessDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path (Join-ChildPath $Workspace @("examples", "risky-change")) | Out-Null
New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null
New-Item -ItemType Directory -Force -Path $Dist | Out-Null
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

$Brief = "examples/risky-change/brief.md"
$ContractPath = "contract.json"
$RunDir = ".covenant/runs"
$RunID = "release-ready"
$LedgerPath = "$RunDir/$RunID/events.ndjson"
$EvidencePath = "$RunDir/$RunID/evidence-pack.json"
$PrivateKey = "covenant-private-key.json"
$PublicKey = "covenant-public-key.json"
$ReleasePublicKey = "covenant-release-public-key.json"
$BundlePath = "release-ready-bundle.zip"
$FilesList = Join-ChildPath $Workspace @("schema-files.txt")

Write-Utf8NoBom -Path (Join-ChildPath $Workspace @($Brief)) -Content ("Create demo-output/report.txt" + [Environment]::NewLine)

# Equivalent command:
# go build -o $Bin ./cmd/covenant
Invoke-Native -Command "go" -Arguments @("build", "-o", $Bin, "./cmd/covenant") -WorkingDirectory $Root

Write-Host "release readiness: workspace=$ReadinessDir"
Write-Host "release readiness: target=$Target version=$Version commit=$Commit date=$Date"

Save-Json -Name "version" -Arguments @("version", "--json")
Save-Json -Name "compile" -Arguments @("compile", "--brief", $Brief, "--out", $ContractPath, "--json")
Save-Json -Name "lint-brief" -Arguments @("lint", "--brief", $Brief, "--json")
Save-Json -Name "lint-contract" -Arguments @("lint", "--contract", $ContractPath, "--json")
Save-Json -Name "run" -Arguments @(
    "run",
    "--contract", $ContractPath,
    "--workspace", $Workspace,
    "--out", $RunDir,
    "--run-id", $RunID,
    "--json"
)
Save-Json -Name "verify" -Arguments @("verify", "--ledger", $LedgerPath, "--evidence", $EvidencePath, "--json")
Save-Json -Name "policy-explain" -Arguments @("policy", "explain", "--evidence", $EvidencePath, "--json")
Save-Json -Name "policy-index" -Arguments @("policy", "index", "--evidence", $EvidencePath, "--json")
Save-Json -Name "policy-spine" -Arguments @("policy", "spine", "--json")

Save-Json -Name "bundle-keygen" -Arguments @("bundle", "keygen", "--private", $PrivateKey, "--public", $PublicKey, "--json")
Save-Json -Name "bundle-export" -Arguments @(
    "bundle", "export",
    "--contract", $ContractPath,
    "--ledger", $LedgerPath,
    "--evidence", $EvidencePath,
    "--workspace", $Workspace,
    "--out", $BundlePath,
    "--sign-key", $PrivateKey,
    "--json"
)
Save-Json -Name "bundle-verify" -Arguments @("verify", "--bundle", $BundlePath, "--public-key", $PublicKey, "--json")
Save-Json -Name "bundle-inspect" -Arguments @("bundle", "inspect", "--bundle", $BundlePath, "--public-key", $PublicKey, "--json")
Save-Json -Name "bundle-report" -Arguments @("bundle", "report", "--bundle", $BundlePath, "--public-key", $PublicKey, "--json")

# Runs the same release package, release verify, release inspect, and schema validate
# checks as the Unix release-readiness gate.
Save-Json -Name "release-package" -Arguments @(
    "release", "package",
    "--source", $Root,
    "--out", $Dist,
    "--version", $Version,
    "--commit", $Commit,
    "--date", $Date,
    "--target", $Target,
    "--sign-key", $PrivateKey,
    "--json"
)
Copy-Item -LiteralPath (Join-ChildPath $Workspace @($PublicKey)) -Destination (Join-ChildPath $Dist @($ReleasePublicKey)) -Force
Invoke-CovenantToFile -Arguments @(
    "release", "verify",
    "--dir", $Dist,
    "--public-key", (Join-ChildPath $Dist @($ReleasePublicKey))
) -OutputPath (Join-ChildPath $Artifacts @("release-verify.txt"))
Save-Json -Name "release-verify" -Arguments @("release", "verify", "--dir", $Dist, "--public-key", (Join-ChildPath $Dist @($ReleasePublicKey)), "--json")
Save-Json -Name "release-inspect" -Arguments @("release", "inspect", "--dir", $Dist, "--public-key", (Join-ChildPath $Dist @($ReleasePublicKey)), "--json")

Invoke-NativeToFile -Command $Bin -Arguments @("version", "--json") -OutputPath (Join-ChildPath $Artifacts @("binary-version.json")) -WorkingDirectory $Workspace
Invoke-NativeToFile -Command $Bin -Arguments @(
    "release", "verify",
    "--dir", $Dist,
    "--public-key", (Join-ChildPath $Dist @($ReleasePublicKey)),
    "--json"
) -OutputPath (Join-ChildPath $Artifacts @("binary-release-verify.json")) -WorkingDirectory $Workspace

$SchemaFiles = @(
    $ContractPath,
    $EvidencePath,
    $PrivateKey,
    $PublicKey,
    "release/manifest.json",
    "release/release-signature.json",
    "release/$ReleasePublicKey"
)
$SchemaFiles += Get-ChildItem -LiteralPath $Artifacts -File -Filter "*.json" |
    Where-Object { $_.Name -ne "schema-validation.json" } |
    Sort-Object Name |
    ForEach-Object { "artifacts/$($_.Name)" }
Write-Utf8NoBom -Path $FilesList -Content (($SchemaFiles -join [Environment]::NewLine) + [Environment]::NewLine)

Invoke-CovenantToFile -Arguments @(
    "schema", "validate",
    "--files-from", $FilesList,
    "--json",
    "--out", (Join-ChildPath $Artifacts @("schema-validation.json"))
) -OutputPath (Join-ChildPath $Artifacts @("schema-validation.stdout"))

$JsonReportCount = @(Get-ChildItem -LiteralPath $Artifacts -File -Filter "*.json").Count
$SummaryValidationReportCount = $JsonReportCount + 1
$ReleaseFileCount = @(Get-ChildItem -LiteralPath $Dist -File).Count

$SummaryObject = [ordered]@{
    schema_version = "covenant.release-readiness-summary.v1"
    status = "passed"
    version = $Version
    commit = $Commit
    date = $Date
    target = $Target
    platform = [ordered]@{
        os = $HostOS
        arch = $HostArch
        script = "scripts/release-readiness.ps1"
    }
    checks = @(
        "version",
        "compile",
        "lint-brief",
        "lint-contract",
        "run",
        "verify",
        "policy-explain",
        "policy-index",
        "policy-spine",
        "bundle-keygen",
        "bundle-export",
        "bundle-verify",
        "bundle-inspect",
        "bundle-report",
        "release-package",
        "release-verify",
        "release-inspect",
        "binary-version",
        "binary-release-verify",
        "schema-validation",
        "release-readiness-summary-validation"
    )
    artifact_counts = [ordered]@{
        json_reports = $SummaryValidationReportCount
        generated_release_files = $ReleaseFileCount
    }
    sensitivity = "summary-only; does not include workspace paths, signing key paths, bundle paths, checksums, manifest entries, or generated release asset names"
}
Write-Utf8NoBom -Path $Summary -Content (($SummaryObject | ConvertTo-Json -Depth 6) + [Environment]::NewLine)

Invoke-CovenantToFile -Arguments @(
    "schema", "validate",
    "--schema", "covenant.release-readiness-summary.v1",
    "--file", $Summary,
    "--json",
    "--out", (Join-ChildPath $Artifacts @("release-readiness-summary-validation.json"))
) -OutputPath (Join-ChildPath $Artifacts @("release-readiness-summary-validation.stdout"))

Write-Host "release readiness complete: $ReadinessDir"
