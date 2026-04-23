param(
    [string]$Version = 'v4.1.1',
    [string]$Repository = 'https://github.com/zyantific/zydis.git',
    [string]$SourcePath,
    [string]$DestinationRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'third_party\zydis')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-ZydisSourceTree
{
    param(
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path))
    {
        return $false
    }

    return (Test-Path (Join-Path $Path 'CMakeLists.txt')) -and
        (Test-Path (Join-Path $Path 'include\Zydis\Zydis.h')) -and
        (Test-Path (Join-Path $Path 'dependencies\zycore\CMakeLists.txt'))
}

function Copy-ZydisTree
{
    param(
        [string]$From,
        [string]$To
    )

    if (Test-Path $To)
    {
        Remove-Item -Recurse -Force $To
    }

    New-Item -ItemType Directory -Force -Path $To | Out-Null

    Get-ChildItem -Path $From -Force |
        Where-Object { $_.Name -notin @('.git', '.github') } |
        ForEach-Object {
            Copy-Item -Path $_.FullName -Destination (Join-Path $To $_.Name) -Recurse -Force
        }
}

if (-not [string]::IsNullOrWhiteSpace($SourcePath))
{
    $resolvedSource = (Resolve-Path $SourcePath).Path

    if (-not (Test-ZydisSourceTree -Path $resolvedSource))
    {
        throw "SourcePath is not a complete Zydis source tree with Zycore: $resolvedSource"
    }

    Copy-ZydisTree -From $resolvedSource -To $DestinationRoot
    Write-Host "Vendored Zydis source: $DestinationRoot"
    Write-Host "You can now run .\\scripts\\Build.ps1 -ZydisSource Vendor -Reconfigure"
    return
}

$git = Get-Command git.exe -ErrorAction SilentlyContinue

if ($null -eq $git)
{
    throw 'git.exe is required unless -SourcePath is provided.'
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("zydis-vendor-" + [guid]::NewGuid().ToString('N'))

try
{
    & $git.Source clone --depth 1 --branch $Version $Repository $tempRoot

    if ($LASTEXITCODE -ne 0)
    {
        throw "git clone failed with exit code $LASTEXITCODE"
    }

    & $git.Source -C $tempRoot submodule update --init --depth 1 --recursive

    if ($LASTEXITCODE -ne 0)
    {
        throw "git submodule update failed with exit code $LASTEXITCODE"
    }

    if (-not (Test-ZydisSourceTree -Path $tempRoot))
    {
        throw "Downloaded source tree is incomplete: $tempRoot"
    }

    Copy-ZydisTree -From $tempRoot -To $DestinationRoot
}
finally
{
    if (Test-Path $tempRoot)
    {
        Remove-Item -Recurse -Force $tempRoot
    }
}

Write-Host "Vendored Zydis source: $DestinationRoot"
Write-Host "Version: $Version"
Write-Host "You can now run .\\scripts\\Build.ps1 -ZydisSource Vendor -Reconfigure"
