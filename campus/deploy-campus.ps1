[CmdletBinding()]
param(
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9.-]*$')][string]$RouterAddress = '192.168.1.1',
    [ValidatePattern('^[a-zA-Z_][a-zA-Z0-9_-]*$')][string]$SshUser = 'admin',
    [ValidateRange(1,65535)][int]$SshPort = 22,
    [string]$IdentityFile,
    [string]$SitePath = (Join-Path $PSScriptRoot 'site.json'),
    [string]$CaPath = (Join-Path $PSScriptRoot 'campus_root_ca.pem')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$root = Split-Path $PSScriptRoot -Parent
$binary = Join-Path $root 'dist/campusctl'
$tempDirectory = $null
$remoteCreated = $false
$remoteStage = $null
$target = "${SshUser}@${RouterAddress}"
function Assert-Exit([string]$operation) { if ($LASTEXITCODE -ne 0) { throw "$operation failed (exit $LASTEXITCODE)." } }
function HashFile([string]$path) {
    $s=[IO.File]::OpenRead($path);$h=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($h.ComputeHash($s)).Replace('-','').ToLowerInvariant() } finally { $h.Dispose();$s.Dispose() }
}
function Write-Lf([string]$path,[string]$data) { [IO.File]::WriteAllText($path,$data.Replace("`r`n","`n").Replace("`r","`n"),[Text.UTF8Encoding]::new($false)) }
try {
    foreach ($path in @($binary,$SitePath,$CaPath,(Join-Path $PSScriptRoot 'page.asp'),(Join-Path $PSScriptRoot 'manager.sh'),(Join-Path $PSScriptRoot 'install.sh'))) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing required file: $path" }
    }
    $expected = ([IO.File]::ReadAllText((Join-Path $root 'dist/campusctl.SHA256')).Trim() -split '\s+')[0]
    if ((HashFile $binary) -ne $expected) { throw 'Local campusctl checksum does not match.' }
    $ssh=(Get-Command ssh.exe -ErrorAction Stop).Source;$scp=(Get-Command scp.exe -ErrorAction Stop).Source;$tar=(Get-Command tar.exe -ErrorAction Stop).Source
    $sshArgs=@('-o','ConnectTimeout=15','-p',"$SshPort");$scpArgs=@('-O','-o','ConnectTimeout=15','-P',"$SshPort")
    if ($IdentityFile) { $IdentityFile=(Resolve-Path -LiteralPath $IdentityFile).Path;$sshArgs+=@('-i',$IdentityFile);$scpArgs+=@('-i',$IdentityFile) }
    $token=[Guid]::NewGuid().ToString('N')
    $tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\','/')
    $tempDirectory=Join-Path $tempRoot "campus-deploy-$token"
    New-Item -ItemType Directory -Path $tempDirectory | Out-Null
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls.exe $tempDirectory /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
    Assert-Exit 'Securing local staging directory'
    $payload=Join-Path $tempDirectory 'payload';New-Item -ItemType Directory -Path $payload | Out-Null
    Copy-Item -LiteralPath $binary -Destination (Join-Path $payload 'campusctl')
    Copy-Item -LiteralPath $CaPath -Destination (Join-Path $payload 'campus_root_ca.pem')
    Write-Lf (Join-Path $payload 'site.json') ([IO.File]::ReadAllText((Resolve-Path -LiteralPath $SitePath).Path))
    foreach ($name in @('page.asp','manager.sh','install.sh')) { Write-Lf (Join-Path $payload $name) ([IO.File]::ReadAllText((Join-Path $PSScriptRoot $name))) }
    $files=@('campusctl','page.asp','manager.sh','install.sh','site.json','campus_root_ca.pem')
    $sums=foreach ($name in $files) { "$(HashFile (Join-Path $payload $name))  $name" }
    Write-Lf (Join-Path $payload 'SHA256SUMS') (($sums -join "`n")+"`n")
    $archive=Join-Path $tempDirectory 'bundle.tar.gz'
    & $tar -czf $archive -C $payload @files SHA256SUMS;Assert-Exit 'Creating addon package'
    $remoteStage="/tmp/campus-deploy-$token"
    & $ssh @sshArgs $target "umask 077; mkdir '$remoteStage' && chmod 700 '$remoteStage'";Assert-Exit 'Creating remote staging directory'
    $remoteCreated=$true
    & $scp @scpArgs $archive "${target}:${remoteStage}/bundle.tar.gz";Assert-Exit 'Uploading addon'
    $remoteCommand="umask 077; cd '$remoteStage' && tar -xzf bundle.tar.gz && sh ./install.sh; result=`$?; cd /tmp; rm -rf '$remoteStage'; exit `$result"
    & $ssh @sshArgs $target $remoteCommand
    if ($LASTEXITCODE -ne 255) { $remoteCreated=$false }
    Assert-Exit 'Installing addon'
    $remoteCreated=$false
    Write-Host 'Campus login addon installed. Use the router management interface to configure it.'
} finally {
    if ($remoteCreated -and $remoteStage -match '^/tmp/campus-deploy-[a-f0-9]{32}$') {
        & $ssh @sshArgs $target "rm -rf '$remoteStage'"
        if ($LASTEXITCODE -ne 0) { Write-Warning "Could not remove remote staging directory: $remoteStage" }
    }
    if ($tempDirectory -and (Test-Path -LiteralPath $tempDirectory)) {
        $resolved=[IO.Path]::GetFullPath($tempDirectory);$prefix=$tempRoot+[IO.Path]::DirectorySeparatorChar+'campus-deploy-'
        if (-not $resolved.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected temporary directory path.' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
