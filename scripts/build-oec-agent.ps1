[CmdletBinding()]
param(
    [string]$OutputDirectory = "work/oec-dist",
    [string]$Version = "0.8.10",
    [string]$ReleaseGithubRepo = 'tikkacn/TY-Gateway'
)

$ErrorActionPreference = "Stop"
if ($ReleaseGithubRepo -and $ReleaseGithubRepo -cnotmatch '^[A-Za-z0-9-]{1,39}/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}$') {
    throw 'ReleaseGithubRepo must be an owner/repository name'
}
$repoRoot = Split-Path -Parent $PSScriptRoot
$go = Join-Path $repoRoot "work/toolchains/go/bin/go.exe"
if (-not (Test-Path -LiteralPath $go)) {
    $go = "go.exe"
}
$out = Join-Path $repoRoot $OutputDirectory
New-Item -ItemType Directory -Force -Path $out | Out-Null

$env:GOOS = "linux"
$env:GOARCH = "arm64"
$env:CGO_ENABLED = "0"
& $go build -trimpath "-ldflags=-s -w -X main.version=$Version" -o (Join-Path $out "gateway-agent-linux-arm64") (Join-Path $repoRoot "cmd/gateway-agent")
if ($LASTEXITCODE -ne 0) {
    throw "gateway-agent ARM64 build failed"
}
$env:GOOS = "linux"
$env:GOARCH = "arm64"
$env:CGO_ENABLED = "0"
& $go build -trimpath -ldflags="-s -w" -o (Join-Path $out "gateway-local-linux-arm64") (Join-Path $repoRoot "cmd/gateway-local")
if ($LASTEXITCODE -ne 0) {
    throw "gateway-local ARM64 build failed"
}
$env:GOOS = "linux"
$env:GOARCH = "arm64"
$env:CGO_ENABLED = "0"
& $go build -trimpath -ldflags="-s -w" -o (Join-Path $out "dae-config-helper-linux-arm64") (Join-Path $repoRoot "cmd/dae-config-helper")
if ($LASTEXITCODE -ne 0) {
    throw "dae-config-helper ARM64 build failed"
}
$releaseFetchLdflags = '-s -w'
if ($ReleaseGithubRepo) { $releaseFetchLdflags += " -X main.githubRepo=$ReleaseGithubRepo" }
& $go build -trimpath "-ldflags=$releaseFetchLdflags" -o (Join-Path $out "ty-release-fetch-linux-arm64") (Join-Path $repoRoot "cmd/ty-release-fetch")
if ($LASTEXITCODE -ne 0) {
    throw "ty-release-fetch ARM64 build failed"
}

$hashLines = Get-ChildItem -LiteralPath $out -File | Where-Object { $_.Name -in @("gateway-agent-linux-arm64", "gateway-local-linux-arm64", "dae-config-helper-linux-arm64", "ty-release-fetch-linux-arm64") } | ForEach-Object {
    $hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
    "{0}  {1}" -f $hash.Hash.ToLowerInvariant(), $_.Name
}
[IO.File]::WriteAllText((Join-Path $out "SHA256SUMS"), (($hashLines -join "`n") + "`n"), [Text.Encoding]::ASCII)
Get-ChildItem -LiteralPath $out -File | Where-Object { $_.Name -in @("gateway-agent-linux-arm64", "gateway-local-linux-arm64", "dae-config-helper-linux-arm64", "ty-release-fetch-linux-arm64") } | ForEach-Object { Write-Output ("Built {0} ({1} bytes)" -f $_.FullName, $_.Length) }
