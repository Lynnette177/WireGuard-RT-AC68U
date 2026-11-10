param([switch]$RunTests)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$goExe = Join-Path $projectRoot '.toolchains/go1.23.12/go/bin/go.exe'
if (-not (Test-Path -LiteralPath $goExe)) { $goExe = (Get-Command go).Source }
$names = @('GOOS', 'GOARCH', 'GOARM', 'CGO_ENABLED', 'GOTOOLCHAIN', 'GOFLAGS', 'GOWORK')
$saved = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
Push-Location (Join-Path $projectRoot 'tools/wgctl')
try {
    $env:GOTOOLCHAIN = 'go1.23.12'
    $env:CGO_ENABLED = '0'
    $env:GOFLAGS = ''
    $env:GOWORK = 'off'
    $env:GOOS = 'windows'; $env:GOARCH = 'amd64'
    if ($RunTests) {
        & $goExe test ./...
        if ($LASTEXITCODE -ne 0) { throw 'wgctl tests failed' }
    }
    & $goExe vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'wgctl vet failed' }
    & $goExe build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o ../../dist/wgctl-check.exe .
    if ($LASTEXITCODE -ne 0) { throw 'Checker build failed' }
    $env:GOOS = 'linux'; $env:GOARCH = 'arm'; $env:GOARM = '7,softfloat'
    & $goExe build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o ../../dist/wgctl .
    if ($LASTEXITCODE -ne 0) { throw 'ARM controller build failed' }
    $sums = foreach ($file in @('wireguard-go', 'wgctl', 'wgctl-check.exe')) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $projectRoot "dist/$file") -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $file"
    }
    [IO.File]::WriteAllText((Join-Path $projectRoot 'dist/SHA256SUMS'), ($sums -join "`n")+"`n", [Text.UTF8Encoding]::new($false))
} finally {
    Pop-Location
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
}
