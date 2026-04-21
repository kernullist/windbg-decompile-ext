param(
    [string]$SourceRoot,
    [string]$HeaderPath,
    [string]$LibraryPath,
    [string]$DestinationRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'third_party\dbgeng')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-FileFromRoot
{
    param(
        [string]$Root,
        [string[]]$RelativeCandidates,
        [string]$FilterName
    )

    if ([string]::IsNullOrWhiteSpace($Root))
    {
        return $null
    }

    foreach ($relativePath in $RelativeCandidates)
    {
        $candidate = Join-Path $Root $relativePath

        if (Test-Path $candidate)
        {
            return $candidate
        }
    }

    $recursiveMatch = Get-ChildItem -Path $Root -Recurse -Filter $FilterName -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName

    if (-not [string]::IsNullOrWhiteSpace($recursiveMatch))
    {
        return $recursiveMatch
    }

    return $null
}

if ([string]::IsNullOrWhiteSpace($HeaderPath))
{
    $HeaderPath = Resolve-FileFromRoot `
        -Root $SourceRoot `
        -RelativeCandidates @('sdk\inc\dbgeng.h', 'inc\dbgeng.h', 'dbgeng.h') `
        -FilterName 'dbgeng.h'
}

if ([string]::IsNullOrWhiteSpace($LibraryPath))
{
    $LibraryPath = Resolve-FileFromRoot `
        -Root $SourceRoot `
        -RelativeCandidates @(
            'sdk\lib\dbgeng.lib',
            'sdk\lib\amd64\dbgeng.lib',
            'sdk\lib\x64\dbgeng.lib',
            'lib\dbgeng.lib',
            'lib\amd64\dbgeng.lib',
            'lib\x64\dbgeng.lib',
            'dbgeng.lib'
        ) `
        -FilterName 'dbgeng.lib'
}

if ([string]::IsNullOrWhiteSpace($HeaderPath) -or -not (Test-Path $HeaderPath))
{
    throw 'Could not resolve dbgeng.h. Provide -HeaderPath or -SourceRoot.'
}

if ([string]::IsNullOrWhiteSpace($LibraryPath) -or -not (Test-Path $LibraryPath))
{
    throw 'Could not resolve dbgeng.lib. Provide -LibraryPath or -SourceRoot.'
}

$destinationIncludeDir = Join-Path $DestinationRoot 'inc'
$destinationLibraryDir = Join-Path $DestinationRoot 'lib'

New-Item -ItemType Directory -Force -Path $destinationIncludeDir | Out-Null
New-Item -ItemType Directory -Force -Path $destinationLibraryDir | Out-Null

Copy-Item -Path $HeaderPath -Destination (Join-Path $destinationIncludeDir 'dbgeng.h') -Force
Copy-Item -Path $LibraryPath -Destination (Join-Path $destinationLibraryDir 'dbgeng.lib') -Force

Write-Host "Vendor dbgeng include: $(Join-Path $destinationIncludeDir 'dbgeng.h')"
Write-Host "Vendor dbgeng library: $(Join-Path $destinationLibraryDir 'dbgeng.lib')"
Write-Host 'You can now run .\scripts\Build.ps1 -Reconfigure without DEBUGGERS_ROOT if this project root is used.'
