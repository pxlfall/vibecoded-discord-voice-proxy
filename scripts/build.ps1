param([Parameter(Mandatory=$true)][string]$VcpkgRoot)
$ErrorActionPreference = 'Stop'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:VCPKG_DISABLE_METRICS = '1'
$root = Split-Path $PSScriptRoot -Parent
$vcpkg = (Resolve-Path $VcpkgRoot).Path
$build = Join-Path $root 'build'
function Run([string]$Program,[string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE) { throw "$Program failed with exit code $LASTEXITCODE" }
}
Run 'cmake' @('-S',$root,'-B',$build,'-G','Visual Studio 17 2022','-A','x64',
    "-DCMAKE_TOOLCHAIN_FILE=$vcpkg/scripts/buildsystems/vcpkg.cmake",
    '-DVCPKG_TARGET_TRIPLET=x64-windows-static','-DVCPKG_HOST_TRIPLET=x64-windows-static')
Run 'cmake' @('--build',$build,'--config','Release','--parallel','4')
Run 'ctest' @('--test-dir',$build,'-C','Release','--output-on-failure')
$payload = Join-Path $build 'payload/Release'
Run 'dotnet' @('publish',(Join-Path $root 'installer/DiscordProxyInstaller.csproj'),
    '-c','Release','-r','win-x64','--self-contained','true',
    '-p:PublishSingleFile=true','-p:IncludeNativeLibrariesForSelfExtract=true',
    "-p:PayloadDirectory=$payload",'-o',(Join-Path $root 'dist'))
