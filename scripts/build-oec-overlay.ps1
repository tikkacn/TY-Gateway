param(
    [Parameter(Position = 0)]
    [string]$OutDir = 'work\oec-overlay',
    [string]$AgentBinary = 'work\oec-dist\gateway-agent-linux-arm64',
    [string]$DaeHelperBinary = 'work\oec-dist\dae-config-helper-linux-arm64',
    [string]$LocalManagerBinary = 'work\oec-dist\gateway-local-linux-arm64',
    [string]$FrpcBinary = 'work\frpc-linux-arm64',
    [string]$ReleaseFetchBinary = 'work\oec-dist\ty-release-fetch-linux-arm64'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$outPath = [IO.Path]::GetFullPath((Join-Path $repoRoot $OutDir))
$agentPath = [IO.Path]::GetFullPath((Join-Path $repoRoot $AgentBinary))
$daeHelperPath = [IO.Path]::GetFullPath((Join-Path $repoRoot $DaeHelperBinary))
$localManagerPath = [IO.Path]::GetFullPath((Join-Path $repoRoot $LocalManagerBinary))
$frpcPath = [IO.Path]::GetFullPath((Join-Path $repoRoot $FrpcBinary))
$releaseFetchPath = [IO.Path]::GetFullPath((Join-Path $repoRoot $ReleaseFetchBinary))
$rootfsPath = Join-Path $repoRoot 'firmware\oec\rootfs'

foreach ($required in @(
    $agentPath,
    $daeHelperPath,
    $localManagerPath,
    $frpcPath,
    $releaseFetchPath,
    (Join-Path $rootfsPath 'etc\systemd\system\ty-gateway-agent.service'),
    (Join-Path $rootfsPath 'etc\systemd\system\ty-gateway-local.service'),
    (Join-Path $rootfsPath 'etc\systemd\system\ty-gateway-network.service'),
    (Join-Path $rootfsPath 'usr\local\libexec\ty-gateway-network'),
    (Join-Path $rootfsPath 'usr\local\libexec\ty_gateway_lan.py'),
    (Join-Path $rootfsPath 'etc\systemd\system\ty-gateway-lan.service'),
    (Join-Path $rootfsPath 'etc\systemd\system\ty-gateway-dae-helper.service'),
    (Join-Path $rootfsPath 'etc\systemd\system\ty-gateway-update-recover.service'),
    (Join-Path $rootfsPath 'etc\systemd\system\ty-gateway-update-service.service'),
    (Join-Path $rootfsPath 'etc\systemd\system\dae.service.d\ty-gateway-forwarding.conf'),
    (Join-Path $rootfsPath 'usr\local\libexec\ty-gateway-dae-preflight'),
    (Join-Path $rootfsPath 'etc\NetworkManager\dispatcher.d\90-ty-gateway-dae-forwarding'),
    (Join-Path $rootfsPath 'usr\local\libexec\ty-gateway-firstboot')
)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required file is missing: $required"
    }
}

if (Test-Path -LiteralPath $outPath) {
    throw "Refusing to overwrite existing output directory: $outPath. Choose a new directory."
}
New-Item -ItemType Directory -Path $outPath -Force | Out-Null
$payload = Join-Path $outPath 'payload'
New-Item -ItemType Directory -Path $payload -Force | Out-Null

function Copy-Payload([string]$RelativeSource, [string]$RelativeTarget) {
    $source = Join-Path $rootfsPath $RelativeSource
    $target = Join-Path $payload $RelativeTarget
    $parent = Split-Path -Parent $target
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $target -Force
}

Copy-Payload 'etc\systemd\system\ty-gateway-firstboot.service' 'etc\systemd\system\ty-gateway-firstboot.service'
Copy-Payload 'etc\systemd\system\ty-gateway-agent.service' 'etc\systemd\system\ty-gateway-agent.service'
Copy-Payload 'etc\systemd\system\ty-gateway-local.service' 'etc\systemd\system\ty-gateway-local.service'
Copy-Payload 'etc\systemd\system\ty-gateway-network.service' 'etc\systemd\system\ty-gateway-network.service'
Copy-Payload 'etc\systemd\system\ty-gateway-lan.service' 'etc\systemd\system\ty-gateway-lan.service'
Copy-Payload 'etc\tmpfiles.d\ty-gateway-lan.conf' 'etc\tmpfiles.d\ty-gateway-lan.conf'
Copy-Payload 'etc\systemd\system\ty-gateway-dae-helper.service' 'etc\systemd\system\ty-gateway-dae-helper.service'
Copy-Payload 'etc\systemd\system\ty-gateway-update-recover.service' 'etc\systemd\system\ty-gateway-update-recover.service'
Copy-Payload 'etc\systemd\system\ty-gateway-update-service.service' 'etc\systemd\system\ty-gateway-update-service.service'
Copy-Payload 'etc\systemd\system\dae.service.d\ty-gateway-forwarding.conf' 'etc\systemd\system\dae.service.d\ty-gateway-forwarding.conf'
Copy-Payload 'etc\systemd\system\ty-frpc-rescue.service' 'etc\systemd\system\ty-frpc-rescue.service'
Copy-Payload 'usr\local\libexec\ty-gateway-firstboot' 'usr\local\libexec\ty-gateway-firstboot'
Copy-Payload 'usr\local\libexec\ty-gateway-network' 'usr\local\libexec\ty-gateway-network'
Copy-Payload 'usr\local\libexec\ty-gateway-dae-preflight' 'usr\local\libexec\ty-gateway-dae-preflight'
Copy-Payload 'etc\NetworkManager\dispatcher.d\90-ty-gateway-dae-forwarding' 'etc\NetworkManager\dispatcher.d\90-ty-gateway-dae-forwarding'
Copy-Payload 'usr\local\libexec\ty_gateway_lan.py' 'usr\local\libexec\ty_gateway_lan.py'
Copy-Payload 'etc\ty-gateway\agent.env.example' 'etc\ty-gateway\agent.env.example'
Copy-Payload 'etc\ty-gateway\local.env.example' 'etc\ty-gateway\local.env.example'
Copy-Payload 'etc\ty-gateway\frpc.toml.example' 'etc\ty-gateway\frpc.toml.example'

New-Item -ItemType Directory -Path (Join-Path $payload 'usr\local\bin') -Force | Out-Null
Copy-Item -LiteralPath $agentPath -Destination (Join-Path $payload 'usr\local\bin\ty-gateway-agent') -Force
Copy-Item -LiteralPath $localManagerPath -Destination (Join-Path $payload 'usr\local\bin\ty-gateway-local') -Force
Copy-Item -LiteralPath $releaseFetchPath -Destination (Join-Path $payload 'usr\local\bin\ty-release-fetch') -Force
Copy-Item -LiteralPath $frpcPath -Destination (Join-Path $payload 'usr\local\bin\frpc') -Force
$helperTarget = Join-Path $payload 'usr\local\libexec'
New-Item -ItemType Directory -Path $helperTarget -Force | Out-Null
Copy-Item -LiteralPath $daeHelperPath -Destination (Join-Path $helperTarget 'ty-gateway-dae-helper') -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ty-gateway-update.py') -Destination (Join-Path $helperTarget 'ty-gateway-update') -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ty-gateway-update-service.py') -Destination (Join-Path $helperTarget 'ty-gateway-update-service') -Force
Copy-Item -LiteralPath (Join-Path $repoRoot 'keys\ty-release-public.pem') -Destination (Join-Path $payload 'etc\ty-gateway\release-public.pem') -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'install-oec-overlay.sh') -Destination (Join-Path $outPath 'install-oec-overlay.sh') -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'restore-oec-overlay.sh') -Destination (Join-Path $outPath 'restore-oec-overlay.sh') -Force
Copy-Item -LiteralPath (Join-Path $repoRoot 'firmware\oec\README.md') -Destination (Join-Path $outPath 'README.md') -Force
Copy-Item -LiteralPath (Join-Path $repoRoot 'firmware\oec\target.json') -Destination (Join-Path $outPath 'target.json') -Force

$manifest = [ordered]@{
    format_version = 1
    package = 'ty-gateway-oec-overlay'
    status = 'boot-preserving-installable-overlay'
    target = 'ordinary OnethingCloud OEC; base image must be validated separately'
    changes = @('install ARM64 Agent with a local password-protected dae rules switch defaulting off', 'install local password-protected OEC management UI as a separate low-privilege user', 'apply DHCP/DNS and MAC/IP settings through a dedicated dnsmasq service on explicit local save', 'apply static OEC IPv4 through a restricted root helper with automatic NetworkManager rollback until new-address login confirmation', 'install root-scoped dae config helper', 'install optional FRPC client', 'install systemd units', 'create low-privilege service users and isolated proxy-control group')
    never_changes = @('/boot', 'Loader', 'DTB', 'partition table', 'existing agent.env', 'existing credentials.json', 'unrelated applications')
    defaults = @{ auto_enroll = $true; frpc_enabled = $false; dae_included = $false; dae_proxy_routing = $false; dhcp_active = $false; lan_dns_active = $false }
    source_sha256 = [ordered]@{
        agent = (Get-FileHash -Algorithm SHA256 -LiteralPath $agentPath).Hash.ToLowerInvariant()
        local_manager = (Get-FileHash -Algorithm SHA256 -LiteralPath $localManagerPath).Hash.ToLowerInvariant()
        dae_helper = (Get-FileHash -Algorithm SHA256 -LiteralPath $daeHelperPath).Hash.ToLowerInvariant()
        frpc = (Get-FileHash -Algorithm SHA256 -LiteralPath $frpcPath).Hash.ToLowerInvariant()
        release_fetch = (Get-FileHash -Algorithm SHA256 -LiteralPath $releaseFetchPath).Hash.ToLowerInvariant()
    }
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $outPath 'overlay-manifest.json') -Encoding utf8

$hashFiles = Get-ChildItem -LiteralPath $outPath -File -Recurse | Where-Object { $_.Name -ne 'SHA256SUMS' } | Sort-Object FullName
$hashLines = foreach ($file in $hashFiles) {
    $relative = $file.FullName.Substring($outPath.Length + 1).Replace('\', '/')
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
    "$hash  $relative"
}
[IO.File]::WriteAllText(
    (Join-Path $outPath 'SHA256SUMS'),
    (($hashLines -join "`n") + "`n"),
    [Text.Encoding]::ASCII
)

$zipPath = "$outPath.zip"
if (Test-Path -LiteralPath $zipPath) {
    throw "Refusing to overwrite existing archive: $zipPath"
}
Compress-Archive -Path (Join-Path $outPath '*') -DestinationPath $zipPath -CompressionLevel Optimal
Write-Output "Created boot-preserving OEC overlay: $outPath"
Write-Output "Created archive: $zipPath"
