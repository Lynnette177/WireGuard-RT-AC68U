param([switch]$RunTests)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$sourcePath = Join-Path $projectRoot 'source'
$distPath = Join-Path $projectRoot 'dist'
$goExe = Join-Path $projectRoot '.toolchains/go1.23.12/go/bin/go.exe'
if (-not (Test-Path -LiteralPath $goExe)) {
    $goExe = (Get-Command go -ErrorAction Stop).Source
}
$savedEnv = @{}
$envNames = @('GOOS', 'GOARCH', 'GOARM', 'CGO_ENABLED', 'GOTOOLCHAIN', 'GOFLAGS', 'GOWORK')
foreach ($name in $envNames) {
    $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
Push-Location $sourcePath
try {
    $env:GOTOOLCHAIN = 'go1.23.12'
    $env:CGO_ENABLED = '0'
    $env:GOFLAGS = ''
    $env:GOWORK = 'off'
    $version = & $goExe version
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '^go version go1\.23\.12 ') {
        throw "Expected Go 1.23.12, got: $version"
    }
    Write-Output $version
    & $goExe mod verify
    if ($LASTEXITCODE -ne 0) { throw 'Dependency verification failed' }
    if ($RunTests) {
        $env:GOOS = (& $goExe env GOHOSTOS)
        $env:GOARCH = (& $goExe env GOHOSTARCH)
        & $goExe test -tags rtac68u ./conn ./device ./replay ./ratelimiter ./tai64n
        if ($LASTEXITCODE -ne 0) { throw 'Host tests failed' }
    }
    $env:GOOS = 'linux'
    $env:GOARCH = 'arm'
    $env:GOARM = '7,softfloat'
    New-Item -ItemType Directory -Force $distPath | Out-Null
    $binary = Join-Path $distPath 'wireguard-go'
    & $goExe build -tags rtac68u -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o $binary .
    if ($LASTEXITCODE -ne 0) { throw 'Cross compilation failed' }
    & $goExe version -m $binary
    if ($LASTEXITCODE -ne 0) { throw 'Build metadata inspection failed' }
    $data = [IO.File]::ReadAllBytes($binary)
    if ([BitConverter]::ToString($data, 0, 6) -ne '7F-45-4C-46-01-01' -or
        [BitConverter]::ToUInt16($data, 18) -ne 40) {
        throw 'Expected little endian ELF32 ARM'
    }
    $phOffset = [BitConverter]::ToUInt32($data, 28)
    $phSize = [BitConverter]::ToUInt16($data, 42)
    $phCount = [BitConverter]::ToUInt16($data, 44)
    for ($i = 0; $i -lt $phCount; $i++) {
        $phType = [BitConverter]::ToUInt32($data, ($phOffset + $i * $phSize))
        if ($phType -eq 2 -or $phType -eq 3) {
            throw 'Unexpected dynamic segment or ELF interpreter'
        }
    }
    $hash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    $sums = foreach ($name in @('wireguard-go', 'wgctl', 'wgctl-check.exe')) {
        $artifact = Join-Path $distPath $name
        if (Test-Path -LiteralPath $artifact) {
            $artifactHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
            "$artifactHash  $name"
        }
    }
    [IO.File]::WriteAllText((Join-Path $distPath 'SHA256SUMS'), ($sums -join "`n")+"`n", [Text.UTF8Encoding]::new($false))
    Write-Output "Verified static ELF32 ARM: $($data.Length) bytes"
    Write-Output "SHA256: $hash"
} finally {
    Pop-Location
    foreach ($name in $envNames) {
        [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], 'Process')
    }
}
