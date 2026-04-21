Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ProjectRoot
{
    return (Split-Path -Parent $PSScriptRoot)
}

function Get-DbgengVendorRoot
{
    return (Join-Path (Get-ProjectRoot) 'third_party\dbgeng')
}

function Test-DbgengIncludeDir
{
    param(
        [string]$IncludeDir
    )

    if ([string]::IsNullOrWhiteSpace($IncludeDir))
    {
        return $false
    }

    $trimmed = $IncludeDir.TrimEnd('\\')
    return (Test-Path (Join-Path $trimmed 'dbgeng.h'))
}

function Test-DbgengLibraryPath
{
    param(
        [string]$LibraryPath
    )

    if ([string]::IsNullOrWhiteSpace($LibraryPath))
    {
        return $false
    }

    return (Test-Path $LibraryPath)
}

function Test-DebuggersRootCandidate
{
    param(
        [string]$Candidate
    )

    if ([string]::IsNullOrWhiteSpace($Candidate))
    {
        return $false
    }

    $layouts = @(
        @{ Header = 'sdk\inc\dbgeng.h'; Library = 'sdk\lib\dbgeng.lib' },
        @{ Header = 'sdk\inc\dbgeng.h'; Library = 'sdk\lib\amd64\dbgeng.lib' },
        @{ Header = 'sdk\inc\dbgeng.h'; Library = 'sdk\lib\x64\dbgeng.lib' },
        @{ Header = 'sdk\inc\dbgeng.h'; Library = 'dbgeng.lib' },
        @{ Header = 'inc\dbgeng.h'; Library = 'lib\dbgeng.lib' },
        @{ Header = 'inc\dbgeng.h'; Library = 'lib\amd64\dbgeng.lib' },
        @{ Header = 'inc\dbgeng.h'; Library = 'lib\x64\dbgeng.lib' },
        @{ Header = 'inc\dbgeng.h'; Library = 'dbgeng.lib' },
        @{ Header = 'dbgeng.h'; Library = 'dbgeng.lib' }
    )

    foreach ($layout in $layouts)
    {
        $headerPath = Join-Path $Candidate $layout.Header
        $libraryPath = Join-Path $Candidate $layout.Library

        if ((Test-Path $headerPath) -and (Test-Path $libraryPath))
        {
            return $true
        }
    }

    return $false
}

function Resolve-DebuggersRoot
{
    param(
        [string]$DebuggersRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($DebuggersRoot))
    {
        $candidate = $DebuggersRoot.TrimEnd('\\')

        if (Test-DebuggersRootCandidate -Candidate $candidate)
        {
            return $candidate
        }

        throw "Invalid DEBUGGERS_ROOT: $candidate"
    }

    $candidates = @(
        (Get-DbgengVendorRoot),
        $env:DEBUGGERS_ROOT,
        $env:DBGENG_ROOT,
        'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64',
        'C:\Program Files\Windows Kits\10\Debuggers\x64'
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($candidate in $candidates)
    {
        $trimmed = $candidate.TrimEnd('\\')

        if (Test-DebuggersRootCandidate -Candidate $trimmed)
        {
            return $trimmed
        }
    }

    throw 'Could not locate Debugging Tools for Windows x64. Set DEBUGGERS_ROOT or provide a third_party\\dbgeng vendor copy first.'
}

function Resolve-DbgengExplicitPaths
{
    param(
        [string]$DbgengIncludeDir,
        [string]$DbgengLibrary
    )

    $hasInclude = -not [string]::IsNullOrWhiteSpace($DbgengIncludeDir)
    $hasLibrary = -not [string]::IsNullOrWhiteSpace($DbgengLibrary)

    if (-not $hasInclude -and -not $hasLibrary)
    {
        return $null
    }

    if (-not $hasInclude -or -not $hasLibrary)
    {
        throw 'DbgengIncludeDir and DbgengLibrary must be provided together.'
    }

    $includeDir = $DbgengIncludeDir.TrimEnd('\\')
    $libraryPath = $DbgengLibrary.TrimEnd('\\')

    if (-not (Test-DbgengIncludeDir -IncludeDir $includeDir))
    {
        throw "Invalid DbgengIncludeDir: $includeDir"
    }

    if (-not (Test-DbgengLibraryPath -LibraryPath $libraryPath))
    {
        throw "Invalid DbgengLibrary: $libraryPath"
    }

    return [pscustomobject]@{
        IncludeDir = $includeDir
        Library = $libraryPath
    }
}

function Resolve-CMakePath
{
    $command = Get-Command cmake.exe -ErrorAction SilentlyContinue

    if ($null -ne $command)
    {
        return $command.Source
    }

    $programFiles = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)}
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($root in $programFiles)
    {
        $candidate = Join-Path $root 'CMake\bin\cmake.exe'

        if (Test-Path $candidate)
        {
            return $candidate
        }
    }

    $vsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'

    if (Test-Path $vsWhere)
    {
        $installationPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath

        if (-not [string]::IsNullOrWhiteSpace($installationPath))
        {
            $candidate = Join-Path $installationPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'

            if (Test-Path $candidate)
            {
                return $candidate
            }
        }
    }

    throw 'Could not locate cmake.exe. Install Visual Studio C++ tools or CMake and retry.'
}

function Invoke-LoggedProcess
{
    param(
        [string]$FilePath,
        [string[]]$ArgumentList
    )

    $rendered = @($FilePath) + $ArgumentList
    Write-Host ('> ' + ($rendered -join ' '))
    & $FilePath @ArgumentList

    if ($LASTEXITCODE -ne 0)
    {
        throw "Command failed with exit code $LASTEXITCODE"
    }
}

function Get-ArtifactPaths
{
    param(
        [string]$BuildDir,
        [string]$Configuration
    )

return [pscustomobject]@{
        Extension = Join-Path $BuildDir "$Configuration\decomp.dll"
    }
}
