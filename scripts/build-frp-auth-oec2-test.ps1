[CmdletBinding()]
param(
    [string]$OutputDirectory = "work/frp-auth-oec2-test-v0.71.0"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$go = Join-Path $repoRoot "work/toolchains/go/bin/go.exe"
if (-not (Test-Path -LiteralPath $go)) {
    $goCommand = Get-Command -Name "go.exe" -ErrorAction SilentlyContinue
    if (-not $goCommand) { throw "Go compiler not found. Run scripts/build-frp-auth.ps1 first to prepare the local toolchain." }
    $go = $goCommand.Source
}
$curl = Get-Command -Name "curl.exe" -ErrorAction SilentlyContinue
$tar = Get-Command -Name "tar.exe" -ErrorAction SilentlyContinue
if (-not $curl) { throw "curl.exe is required to fetch the pinned FRP release archive." }
if (-not $tar) { throw "tar.exe is required to unpack the pinned FRP release archive." }

$out = Join-Path $repoRoot $OutputDirectory
if (Test-Path -LiteralPath $out) {
    throw "Output directory already exists; choose a new -OutputDirectory to avoid overwriting files: $out"
}
$payload = Join-Path $out "payload"
$stage = Join-Path $out "_upstream"
$archive = Join-Path $out "frp_0.71.0_linux_arm64.tar.gz"
New-Item -ItemType Directory -Force -Path $payload, $stage | Out-Null

$frpUrl = "https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_linux_arm64.tar.gz"
$expectedFrpSha256 = "f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266"
& $curl.Source --location --fail --show-error --retry 3 --retry-all-errors --connect-timeout 20 --max-time 600 --output $archive $frpUrl
if ($LASTEXITCODE -ne 0) { throw "FRP release download failed (curl exit $LASTEXITCODE)" }
$actualFrpSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualFrpSha256 -ne $expectedFrpSha256) {
    throw "FRP 0.71.0 ARM64 archive SHA-256 mismatch: $actualFrpSha256"
}

& $tar.Source -xzf $archive -C $stage
if ($LASTEXITCODE -ne 0) { throw "Could not unpack FRP release archive" }
$frps = Get-ChildItem -LiteralPath $stage -Filter frps -File -Recurse | Select-Object -First 1
$frpc = Get-ChildItem -LiteralPath $stage -Filter frpc -File -Recurse | Select-Object -First 1
if (-not $frps -or -not $frpc) { throw "FRP release archive did not contain both frps and frpc" }
Copy-Item -LiteralPath $frps.FullName -Destination (Join-Path $payload "frps")
Copy-Item -LiteralPath $frpc.FullName -Destination (Join-Path $payload "frpc")

$oldGoos = $env:GOOS
$oldGoarch = $env:GOARCH
$oldCgo = $env:CGO_ENABLED
try {
    $env:GOOS = "linux"
    $env:GOARCH = "arm64"
    $env:CGO_ENABLED = "0"
    & $go test -c -trimpath -buildvcs=false -o (Join-Path $payload "frpauth.test") (Join-Path $repoRoot "internal/frpauth")
    if ($LASTEXITCODE -ne 0) { throw "Linux/ARM64 FRP integration test build failed" }
}
finally {
    $env:GOOS = $oldGoos
    $env:GOARCH = $oldGoarch
    $env:CGO_ENABLED = $oldCgo
}

Copy-Item -LiteralPath (Join-Path $repoRoot "docs/FRP-AUTH-OEC2-TEST.md") -Destination (Join-Path $out "README.md")
$hashLines = Get-ChildItem -LiteralPath $payload -File | Sort-Object Name | ForEach-Object {
    $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "{0}  payload/{1}" -f $hash, $_.Name
}
[IO.File]::WriteAllText((Join-Path $out "SHA256SUMS"), (($hashLines -join "`n") + "`n"), [Text.Encoding]::ASCII)
$zipPath = Join-Path $out "ty-frp-auth-oec2-test-v0.71.0.zip"
Compress-Archive -Path (Join-Path $out "README.md"), (Join-Path $out "SHA256SUMS"), $payload -DestinationPath $zipPath -CompressionLevel Optimal
Write-Output "FRP archive SHA-256 verified: $actualFrpSha256"
Write-Output "Built local-only OEC2 integration test kit: $out"
Write-Output "Copy this package to OEC2: $zipPath"
Get-ChildItem -LiteralPath $payload -File | ForEach-Object { Write-Output ("{0} ({1} bytes)" -f $_.Name, $_.Length) }
