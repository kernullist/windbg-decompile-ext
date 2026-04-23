param(
    [string]$Generator = 'Visual Studio 17 2022',
    [string]$Architecture = 'x64',
    [string]$Configuration = 'Release',
    [string]$SourceDir = (Split-Path -Parent $PSScriptRoot),
    [string]$BuildDir,
    [ValidateSet('Auto', 'Vendor', 'Fetch')]
    [string]$ZydisSource = 'Auto',
    [string]$ZydisVendorDir,
    [string]$DebuggersRoot = $env:DEBUGGERS_ROOT,
    [string]$DbgengIncludeDir,
    [string]$DbgengLibrary,
    [switch]$LegacyDbgeng,
    [switch]$Reconfigure,
    [switch]$Clean,
    [switch]$ConfigureOnly,
    [switch]$Verbose
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'BuildCommon.ps1')

if ([string]::IsNullOrWhiteSpace($BuildDir))
{
    $defaultName = if ($LegacyDbgeng) { 'build-legacy' } else { 'build' }
    $BuildDir = Join-Path $SourceDir $defaultName
}

$resolvedExplicitDbgeng = Resolve-DbgengExplicitPaths -DbgengIncludeDir $DbgengIncludeDir -DbgengLibrary $DbgengLibrary
$resolvedDebuggersRoot = $null
$cmake = Resolve-CMakePath
$symbolApis = if ($LegacyDbgeng) { 'OFF' } else { 'ON' }

if ($null -eq $resolvedExplicitDbgeng)
{
    $resolvedDebuggersRoot = Resolve-DebuggersRoot -DebuggersRoot $DebuggersRoot
}

Write-Host "Using cmake=$cmake"
Write-Host "Using SourceDir=$SourceDir"
Write-Host "Using BuildDir=$BuildDir"
Write-Host "Using Configuration=$Configuration"
Write-Host "Using DECOMP_ZYDIS_SOURCE=$($ZydisSource.ToLowerInvariant())"
Write-Host "Using DECOMP_USE_SYMBOL_ENTRY_APIS=$symbolApis"

if (-not [string]::IsNullOrWhiteSpace($ZydisVendorDir))
{
    Write-Host "Using DECOMP_VENDORED_ZYDIS_DIR=$ZydisVendorDir"
}

if ($null -ne $resolvedExplicitDbgeng)
{
    Write-Host "Using DBGENG_INCLUDE_DIR=$($resolvedExplicitDbgeng.IncludeDir)"
    Write-Host "Using DBGENG_LIBRARY=$($resolvedExplicitDbgeng.Library)"
}
else
{
    Write-Host "Using DEBUGGERS_ROOT=$resolvedDebuggersRoot"
}

if ($Clean -and (Test-Path $BuildDir))
{
    Write-Host "Removing build directory $BuildDir"
    Remove-Item -Recurse -Force $BuildDir
}

$needsConfigure = $Reconfigure -or -not (Test-Path (Join-Path $BuildDir 'CMakeCache.txt'))

if ($needsConfigure)
{
    $configureArgs = @(
        '-S', $SourceDir,
        '-B', $BuildDir,
        '-G', $Generator,
        '-A', $Architecture,
        "-DDECOMP_ZYDIS_SOURCE=$($ZydisSource.ToLowerInvariant())",
        "-DDECOMP_USE_SYMBOL_ENTRY_APIS=$symbolApis"
    )

    if (-not [string]::IsNullOrWhiteSpace($ZydisVendorDir))
    {
        $configureArgs += "-DDECOMP_VENDORED_ZYDIS_DIR=$ZydisVendorDir"
    }

    if ($null -ne $resolvedExplicitDbgeng)
    {
        $configureArgs += "-DDBGENG_INCLUDE_DIR=$($resolvedExplicitDbgeng.IncludeDir)"
        $configureArgs += "-DDBGENG_LIBRARY=$($resolvedExplicitDbgeng.Library)"
    }
    else
    {
        $configureArgs += "-DDEBUGGERS_ROOT=$resolvedDebuggersRoot"
    }

    Invoke-LoggedProcess -FilePath $cmake -ArgumentList $configureArgs
}
else
{
    Write-Host 'Skipping configure step because CMakeCache.txt already exists. Use -Reconfigure to force it.'
}

if (-not $ConfigureOnly)
{
    $buildArgs = @(
        '--build', $BuildDir,
        '--config', $Configuration,
        '--parallel'
    )

    if ($Verbose)
    {
        $buildArgs += '--verbose'
    }

    Invoke-LoggedProcess -FilePath $cmake -ArgumentList $buildArgs
}

$artifacts = Get-ArtifactPaths -BuildDir $BuildDir -Configuration $Configuration
Write-Host "Extension artifact: $($artifacts.Extension)"
