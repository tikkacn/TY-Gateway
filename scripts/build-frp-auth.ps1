[CmdletBinding()]
param(
    [ValidateSet("amd64", "arm64")]
    [string]$GoArch = "amd64",
    [string]$OutputDirectory = "work/frp-auth-dist"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$go = Join-Path $repoRoot "work/toolchains/go/bin/go.exe"
if (-not (Test-Path -LiteralPath $go)) {
    $go = "go.exe"
}
$goCommand = Get-Command -Name $go -ErrorAction SilentlyContinue
if (-not $goCommand) {
    throw "Go compiler not found. Install Go or place it at work/toolchains/go/bin/go.exe."
}
$go = $goCommand.Source
$out = Join-Path $repoRoot $OutputDirectory
New-Item -ItemType Directory -Force -Path $out | Out-Null
$binaryName = "ty-frp-auth-linux-$GoArch"
$binaryPath = Join-Path $out $binaryName

$oldGoos = $env:GOOS
$oldGoarch = $env:GOARCH
$oldCgo = $env:CGO_ENABLED
try {
    $env:GOOS = "linux"
    $env:GOARCH = $GoArch
    $env:CGO_ENABLED = "0"
    & $go build -trimpath -buildvcs=false "-ldflags=-s -w" -o $binaryPath (Join-Path $repoRoot "cmd/ty-frp-auth")
    if ($LASTEXITCODE -ne 0) {
        throw "ty-frp-auth Linux/$GoArch build failed"
    }
}
finally {
    $env:GOOS = $oldGoos
    $env:GOARCH = $oldGoarch
    $env:CGO_ENABLED = $oldCgo
}

$hash = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$binaryPath.sha256", "$hash  $binaryName`n", [Text.Encoding]::ASCII)
Write-Output "Built $binaryPath ($((Get-Item -LiteralPath $binaryPath).Length) bytes)"
Write-Output "Checksum: $binaryPath.sha256"
