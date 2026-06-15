[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$ReleaseDir,

    [string]$Repo = "uesugitorachiyo/ao-covenant",

    [string]$Out = "",

    [switch]$SkipAttestation,

    [string]$CovenantBin = $env:COVENANT_BIN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Show-Usage {
    @"
Usage: .\release-consumer-smoke.ps1 <release-dir> [-Repo owner/repo] [-Out dir] [-SkipAttestation] [-CovenantBin path]

Runs the public Windows consumer verification smoke test for a downloaded AO
Covenant release directory. Set COVENANT_BIN or pass -CovenantBin to use a
specific covenant binary; otherwise the script uses covenant from PATH.

Required release files:
  manifest.json
  SHA256SUMS
  release-signature.json
  covenant-release-public-key.json

Do not paste private keys, credentials, production evidence bundles, unreleased bundles, or local machine paths into public issues when reporting failures.
"@
}

function Fail {
    param([string]$Message)
    Write-Error "release consumer smoke: $Message"
    exit 1
}

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Fail "missing required command: $Name"
    }
}

function Require-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Fail "missing required release file: $Path"
    }
}

function Invoke-Native {
    param(
        [string]$Command,
        [string[]]$Arguments
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "command failed with exit code ${LASTEXITCODE}: $Command $($Arguments -join ' ')"
    }
}

function Invoke-NativeToFile {
    param(
        [string]$Command,
        [string[]]$Arguments,
        [string]$OutputPath
    )
    & $Command @Arguments | Set-Content -LiteralPath $OutputPath -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        Fail "command failed with exit code ${LASTEXITCODE}: $Command $($Arguments -join ' ')"
    }
}

if ([string]::IsNullOrWhiteSpace($CovenantBin)) {
    $CovenantBin = "covenant"
}

if (-not (Test-Path -LiteralPath $ReleaseDir -PathType Container)) {
    Show-Usage
    Fail "release directory does not exist: $ReleaseDir"
}

$ReleaseDirPath = (Resolve-Path -LiteralPath $ReleaseDir).Path
$PublicKey = Join-Path $ReleaseDirPath "covenant-release-public-key.json"

if ([string]::IsNullOrWhiteSpace($Out)) {
    $OutDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ao-covenant-release-smoke-" + [System.Guid]::NewGuid().ToString("N"))
}
else {
    $OutDir = $Out
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path

Require-Command $CovenantBin
if (-not $SkipAttestation) {
    Require-Command "gh"
}

Require-File (Join-Path $ReleaseDirPath "manifest.json")
Require-File (Join-Path $ReleaseDirPath "SHA256SUMS")
Require-File (Join-Path $ReleaseDirPath "release-signature.json")
Require-File $PublicKey

Write-Host "release consumer smoke: release=$ReleaseDirPath"
Write-Host "release consumer smoke: outputs=$OutDir"

$ChecksumPath = Join-Path $ReleaseDirPath "SHA256SUMS"
foreach ($Line in Get-Content -LiteralPath $ChecksumPath) {
    $Trimmed = $Line.Trim()
    if ($Trimmed.Length -eq 0) {
        continue
    }
    $Parts = $Trimmed -split "\s+"
    if ($Parts.Count -lt 2) {
        Fail "invalid checksum line: $Line"
    }
    $Expected = $Parts[0].ToLowerInvariant()
    $RelativePath = $Parts[-1].TrimStart("*")
    $ArtifactPath = Join-Path $ReleaseDirPath $RelativePath
    Require-File $ArtifactPath
    $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $ArtifactPath).Hash.ToLowerInvariant()
    if ($Actual -ne $Expected) {
        Fail "checksum mismatch for $RelativePath"
    }
    Write-Host "$RelativePath`: OK"
}

$VerifyJson = Join-Path $OutDir "release-verify.json"
$ReportJson = Join-Path $OutDir "release-report.json"
$InspectJson = Join-Path $OutDir "release-inspect.json"

# Equivalent public command:
# covenant release verify --dir $ReleaseDirPath --public-key $PublicKey --json
Invoke-NativeToFile -Command $CovenantBin -Arguments @("release", "verify", "--dir", $ReleaseDirPath, "--public-key", $PublicKey, "--json") -OutputPath $VerifyJson

# Equivalent public command:
# covenant release report --dir $ReleaseDirPath --public-key $PublicKey --format json --out (Join-Path $OutDir "release-report.json")
Invoke-Native -Command $CovenantBin -Arguments @("release", "report", "--dir", $ReleaseDirPath, "--public-key", $PublicKey, "--format", "json", "--out", $ReportJson)

# Equivalent public command:
# covenant release inspect --dir $ReleaseDirPath --public-key $PublicKey --json
Invoke-NativeToFile -Command $CovenantBin -Arguments @("release", "inspect", "--dir", $ReleaseDirPath, "--public-key", $PublicKey, "--json") -OutputPath $InspectJson

# Equivalent public commands:
# covenant schema validate --file (Join-Path $OutDir "release-verify.json")
# covenant schema validate --file (Join-Path $OutDir "release-report.json")
# covenant schema validate --file (Join-Path $OutDir "release-inspect.json")
Invoke-Native -Command $CovenantBin -Arguments @("schema", "validate", "--file", $VerifyJson)
Invoke-Native -Command $CovenantBin -Arguments @("schema", "validate", "--file", $ReportJson)
Invoke-Native -Command $CovenantBin -Arguments @("schema", "validate", "--file", $InspectJson)

$ReplacementPolicy = Join-Path $ReleaseDirPath "release-replacement-policy.json"
if (Test-Path -LiteralPath $ReplacementPolicy -PathType Leaf) {
    Invoke-Native -Command $CovenantBin -Arguments @("schema", "validate", "--schema", "covenant.release-replacement-policy.v1", "--file", $ReplacementPolicy)
}

if (-not $SkipAttestation) {
    # Equivalent public command:
    # gh attestation verify (Join-Path $ReleaseDirPath "manifest.json") --repo $Repo
    gh attestation verify (Join-Path $ReleaseDirPath "manifest.json") --repo $Repo
    if ($LASTEXITCODE -ne 0) {
        Fail "gh attestation verification failed"
    }
}

Write-Host "release consumer smoke complete: outputs=$OutDir"
