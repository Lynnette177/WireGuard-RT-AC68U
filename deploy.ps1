[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'conf.txt'),
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9.-]*$')]
    [string]$RouterAddress = '192.168.1.1',
    [ValidateRange(1, 65535)][int]$SshPort = 22,
    [ValidatePattern('^[a-zA-Z_][a-zA-Z0-9_-]*$')][string]$SshUser = 'admin',
    [string]$IdentityFile,
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$dist = Join-Path $PSScriptRoot 'dist'
$checker = Join-Path $dist 'wgctl-check.exe'
$daemon = Join-Path $dist 'wireguard-go'
$controller = Join-Path $dist 'wgctl'
$routerScripts = Join-Path $PSScriptRoot 'router'
$tempDirectory = $null
$remoteStage = $null
$remoteCreated = $false
$target = "${SshUser}@${RouterAddress}"

function Assert-ExitCode([string]$Operation) {
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed (exit $LASTEXITCODE)." }
}
function Write-Utf8Lf([string]$Path, [string]$Content) {
    $normalized = $Content.Replace("`r`n", "`n").Replace("`r", "`n")
    [IO.File]::WriteAllText($Path, $normalized, [Text.UTF8Encoding]::new($false))
}
function Get-Sha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

try {
    $ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
    foreach ($file in @($checker, $daemon, $controller, (Join-Path $routerScripts 'service.sh'), (Join-Path $routerScripts 'install.sh'), (Join-Path $routerScripts 'uninstall.sh'))) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Required file is missing: $file" }
    }
    $expected = @{}
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $dist 'SHA256SUMS'))) {
        if ($line -match '^([a-fA-F0-9]{64})\s+\*?(.+)$') { $expected[$Matches[2]] = $Matches[1] }
    }
    foreach ($name in @('wireguard-go', 'wgctl', 'wgctl-check.exe')) {
        $actual = Get-Sha256 (Join-Path $dist $name)
        if (-not $expected.ContainsKey($name) -or $actual -ine $expected[$name]) { throw "Local integrity check failed: $name" }
    }
    # Validation happens before SSH/SCP, without DNS lookup or key logging.
    $managementIp = $null
    $checkerArgs = @('validate', '-config', $ConfigPath)
    if ([Net.IPAddress]::TryParse($RouterAddress, [ref]$managementIp) -and
        $managementIp.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        $checkerArgs += @('-management', $managementIp.ToString())
    }
    & $checker @checkerArgs
    Assert-ExitCode 'Local configuration validation (replace all redacted values in conf.txt)'
    Write-Host 'Deployment policy: IPv4 AllowedIPs from conf.txt configure peer routes and LAN forwarding.'
    Write-Host 'Router DNS and the default gateway are preserved. conf.txt is not modified.'
    if ($ValidateOnly) {
        Write-Host 'Offline checks passed. No router connection was made.'
        return
    }
    $ssh = (Get-Command ssh.exe -ErrorAction Stop).Source
    $scp = (Get-Command scp.exe -ErrorAction Stop).Source
    $tar = (Get-Command tar.exe -ErrorAction Stop).Source
    $sshArgs = @('-o', 'ConnectTimeout=15', '-p', "$SshPort")
    $scpArgs = @('-O', '-o', 'ConnectTimeout=15', '-P', "$SshPort")
    if ($IdentityFile) {
        $IdentityFile = (Resolve-Path -LiteralPath $IdentityFile).Path
        $sshArgs += @('-i', $IdentityFile)
        $scpArgs += @('-i', $IdentityFile)
    }
    $token = [Guid]::NewGuid().ToString('N')
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
    $tempDirectory = Join-Path $tempRoot "wg68-deploy-$token"
    New-Item -ItemType Directory -Path $tempDirectory | Out-Null
    # Restrict the staging directory before copying any real configuration.
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls.exe $tempDirectory /inheritance:r /grant:r "*${currentSid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
    Assert-ExitCode 'Securing local staging directory'
    $payload = Join-Path $tempDirectory 'payload'
    New-Item -ItemType Directory -Path $payload | Out-Null
    Copy-Item -LiteralPath $daemon -Destination (Join-Path $payload 'wireguard-go')
    Copy-Item -LiteralPath $controller -Destination (Join-Path $payload 'wgctl')
    Write-Utf8Lf (Join-Path $payload 'wg0.conf') ([IO.File]::ReadAllText($ConfigPath))
    foreach ($name in @('service.sh', 'install.sh', 'uninstall.sh')) {
        Write-Utf8Lf (Join-Path $payload $name) ([IO.File]::ReadAllText((Join-Path $routerScripts $name)))
    }
    $packageFiles = @('wireguard-go', 'wgctl', 'wg0.conf', 'service.sh', 'install.sh', 'uninstall.sh')
    $sums = foreach ($name in $packageFiles) {
        $hash = Get-Sha256 (Join-Path $payload $name)
        "$hash  $name"
    }
    Write-Utf8Lf (Join-Path $payload 'SHA256SUMS') (($sums -join "`n") + "`n")
    $archive = Join-Path $tempDirectory 'bundle.tar.gz'
    & $tar -czf $archive -C $payload @packageFiles SHA256SUMS
    Assert-ExitCode 'Creating deployment archive'
    $remoteStage = "/tmp/wg68-deploy-$token"
    Write-Host "Connecting to $target. Enable router LAN SSH first; enter the router password when requested."
    # No host-key checks are disabled. First connection may ask to trust the key.
    & $ssh @sshArgs $target "umask 077; mkdir '$remoteStage' && chmod 700 '$remoteStage'"
    Assert-ExitCode 'Creating private remote staging directory'
    $remoteCreated = $true
    & $scp @scpArgs $archive "${target}:${remoteStage}/bundle.tar.gz"
    Assert-ExitCode 'Uploading deployment bundle'
    $remoteCommand = "umask 077; cd '$remoteStage' && tar -xzf bundle.tar.gz && sh ./install.sh; result=`$?; cd /tmp; rm -rf '$remoteStage'; exit `$result"
    & $ssh @sshArgs $target $remoteCommand
    if ($LASTEXITCODE -ne 255) { $remoteCreated = $false }
    Assert-ExitCode 'Remote install/start (see preceding output; failed installation restores previous files)'
    $remoteCreated = $false
    Write-Host ''
    Write-Host 'Installed and started. Boot hooks are installed; DNS is unchanged.'
    Write-Host "Status: ssh -p $SshPort $target /jffs/wireguard/service.sh status"
    Write-Host 'A handshake is required before remote LAN access works; zero handshake time means it is still pending.'
} finally {
    if ($remoteCreated -and $remoteStage -match '^/tmp/wg68-deploy-[a-f0-9]{32}$') {
        # Best-effort removal of the private upload if transfer/installation failed.
        & $ssh @sshArgs $target "rm -rf '$remoteStage'"
        if ($LASTEXITCODE -ne 0) { Write-Warning "Could not remove remote staging directory: $remoteStage" }
    }
    if ($tempDirectory -and (Test-Path -LiteralPath $tempDirectory)) {
        $resolvedTemp = [IO.Path]::GetFullPath($tempDirectory)
        $allowedPrefix = $tempRoot + [IO.Path]::DirectorySeparatorChar + 'wg68-deploy-'
        if (-not $resolvedTemp.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing unexpected temporary directory cleanup path.' }
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
}
