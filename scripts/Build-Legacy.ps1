param(
    [string]$Generator = 'Visual Studio 17 2022',
    [string]$Architecture = 'x64',
    [string]$Configuration = 'Release',
    [string]$SourceDir = (Split-Path -Parent $PSScriptRoot),
    [string]$BuildDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'build-legacy'),
    [ValidateSet('Auto', 'Vendor', 'Fetch')]
    [string]$ZydisSource = 'Auto',
    [string]$ZydisVendorDir,
    [string]$DebuggersRoot = $env:DEBUGGERS_ROOT,
    [string]$DbgengIncludeDir,
    [string]$DbgengLibrary,
    [switch]$Reconfigure,
    [switch]$Clean,
    [switch]$ConfigureOnly,
    [switch]$Verbose
)

$scriptPath = Join-Path $PSScriptRoot 'Build.ps1'

& $scriptPath `
    -Generator $Generator `
    -Architecture $Architecture `
    -Configuration $Configuration `
    -SourceDir $SourceDir `
    -BuildDir $BuildDir `
    -ZydisSource $ZydisSource `
    -ZydisVendorDir $ZydisVendorDir `
    -DebuggersRoot $DebuggersRoot `
    -DbgengIncludeDir $DbgengIncludeDir `
    -DbgengLibrary $DbgengLibrary `
    -LegacyDbgeng `
    -Reconfigure:$Reconfigure `
    -Clean:$Clean `
    -ConfigureOnly:$ConfigureOnly `
    -Verbose:$Verbose

if ($LASTEXITCODE -ne 0)
{
    exit $LASTEXITCODE
}
