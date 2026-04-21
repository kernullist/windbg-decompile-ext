param(
    [string]$Generator = 'Visual Studio 17 2022',
    [string]$Architecture = 'x64',
    [string]$Configuration = 'Release',
    [string]$SourceDir = (Split-Path -Parent $PSScriptRoot),
    [string]$BuildDir,
    [string]$DebuggersRoot = $env:DEBUGGERS_ROOT,
    [string]$DbgengIncludeDir,
    [string]$DbgengLibrary,
    [string]$VersionFile = (Join-Path (Split-Path -Parent $PSScriptRoot) 'version.txt'),
    [switch]$LegacyDbgeng,
    [switch]$Clean,
    [switch]$SkipBuild,
    [switch]$Verbose
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-FileVersionString
{
    param(
        [string]$Path
    )

    if (-not (Test-Path $Path))
    {
        throw "Version file not found: $Path"
    }

    $value = (Get-Content -Path $Path -Raw).Trim()

    if ($value -notmatch '^\d+\.\d+\.\d+\.\d+$')
    {
        throw "Version file must contain a four-part numeric version like 1.0.0.0: $Path"
    }

    return $value
}

function Get-IncrementedBuildVersion
{
    param(
        [string]$Version
    )

    $parts = $Version.Split('.')
    $parts[3] = ([int]$parts[3] + 1).ToString()
    return ($parts -join '.')
}

function Set-FileVersionString
{
    param(
        [string]$Path,
        [string]$Version
    )

    Set-Content -Path $Path -Value $Version -NoNewline
}

$currentVersion = Get-FileVersionString -Path $VersionFile
$nextVersion = Get-IncrementedBuildVersion -Version $currentVersion

Write-Host "Release version: $currentVersion -> $nextVersion"
Set-FileVersionString -Path $VersionFile -Version $nextVersion

if ($SkipBuild)
{
    Write-Host "Updated $VersionFile"
    return
}

$buildScript = Join-Path $PSScriptRoot 'Build.ps1'
$buildParams = @{
    Generator = $Generator
    Architecture = $Architecture
    Configuration = $Configuration
    SourceDir = $SourceDir
    DebuggersRoot = $DebuggersRoot
    Reconfigure = $true
    Clean = $Clean
    Verbose = $Verbose
}

if (-not [string]::IsNullOrWhiteSpace($BuildDir))
{
    $buildParams.BuildDir = $BuildDir
}

if (-not [string]::IsNullOrWhiteSpace($DbgengIncludeDir))
{
    $buildParams.DbgengIncludeDir = $DbgengIncludeDir
}

if (-not [string]::IsNullOrWhiteSpace($DbgengLibrary))
{
    $buildParams.DbgengLibrary = $DbgengLibrary
}

if ($LegacyDbgeng)
{
    $buildParams.LegacyDbgeng = $true
}

try
{
    & $buildScript @buildParams

    if ($LASTEXITCODE -ne 0)
    {
        throw "Build failed with exit code $LASTEXITCODE"
    }
}
catch
{
    Write-Warning "Release build failed. Restoring $VersionFile to $currentVersion."
    Set-FileVersionString -Path $VersionFile -Version $currentVersion
    throw
}

Write-Host "Release build completed with file version $nextVersion"
