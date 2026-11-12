param([switch]$RunTests)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$goExe = Join-Path $root '.toolchains/go1.23.12/go/bin/go.exe'
if (-not (Test-Path -LiteralPath $goExe)) { $goExe = (Get-Command go -ErrorAction Stop).Source }
$names = @('GOOS','GOARCH','GOARM','CGO_ENABLED','GOTOOLCHAIN','GOFLAGS','GOWORK')
$saved = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name,'Process') }
Push-Location (Join-Path $root 'tools/campusctl')
try {
    $env:GOTOOLCHAIN = 'go1.23.12'; $env:CGO_ENABLED = '0'; $env:GOFLAGS = ''; $env:GOWORK = 'off'
    $env:GOOS = 'windows'; $env:GOARCH = 'amd64'
    if ($RunTests) { & $goExe test ./...; if ($LASTEXITCODE -ne 0) { throw 'Campus tests failed' } }
    & $goExe vet ./...; if ($LASTEXITCODE -ne 0) { throw 'Campus vet failed' }
    $env:GOOS = 'linux'; $env:GOARCH = 'arm'; $env:GOARM = '7,softfloat'
    $bin = Join-Path $root 'dist/campusctl'
    & $goExe build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o $bin .
    if ($LASTEXITCODE -ne 0) { throw 'Campus ARM build failed' }
    & $goExe version -m $bin
    if ($LASTEXITCODE -ne 0) { throw 'Campus metadata inspection failed' }
    $hash = (Get-FileHash -LiteralPath $bin -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $root 'dist/campusctl.SHA256'), "$hash  campusctl`n", [Text.UTF8Encoding]::new($false))
} finally {
    Pop-Location
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name,$saved[$name],'Process') }
}
