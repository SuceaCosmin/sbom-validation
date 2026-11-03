<#
.SYNOPSIS
    Builds the standalone sbom-validation executable into dist\ (git-ignored).

.DESCRIPTION
    Reuses the project's Poetry environment (no second environment). Adds only
    the 'build' group (PyInstaller) on top of what is already installed, using
    the versions pinned in poetry.lock, then runs PyInstaller. PyInstaller
    bundles only what the entry point imports, so docs and test packages in the
    environment do not end up in the executable.

.PARAMETER Clean
    Delete build\ and dist\ before building.

.EXAMPLE
    .\scripts\build-exe.ps1 -Clean
#>
param([switch]$Clean)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Invoke-Native {
    param([string]$Command, [string[]]$Arguments)
    Write-Host "+ $Command $($Arguments -join ' ')"
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command failed with exit code $LASTEXITCODE" }
}

if ($Clean) {
    foreach ($folder in 'build', 'dist') {
        if (Test-Path $folder) { Remove-Item -Recurse -Force $folder }
    }
}

# Additive (no --sync): installs PyInstaller and the project itself (so its
# package metadata, i.e. the reported tool version, can be bundled) and leaves
# any other installed groups alone.
Invoke-Native poetry @('install', '--with', 'build')

# jsonschema optionally imports these (remote $ref fetching, format checkers).
# The tool is offline and does not use format checking, but PyInstaller would
# bundle any of them that happen to be installed (e.g. 'requests' from the docs
# group). Excluding them keeps the executable independent of the environment.
$optional = 'requests', 'urllib3', 'certifi', 'charset_normalizer', 'idna',
    'rfc3987', 'rfc3987_syntax', 'rfc3339_validator', 'rfc3986_validator',
    'webcolors', 'fqdn', 'isoduration', 'jsonpointer', 'uri_template'
$excludes = $optional | ForEach-Object { '--exclude-module'; $_ }

Invoke-Native poetry @(
    'run', 'pyinstaller',
    '--noconfirm', '--clean', '--onefile',
    '--name', 'sbom-validation',
    '--distpath', 'dist',
    '--workpath', 'build\pyinstaller',
    '--specpath', 'build',
    '--collect-data', 'sbom_validation',
    '--collect-data', 'jsonschema_specifications',
    '--collect-data', 'license_expression',
    '--copy-metadata', 'sbom-validation'
    $excludes
    'src\sbom_validation\__main__.py'
)

$exe = Get-Item (Join-Path $root 'dist\sbom-validation.exe')
Write-Host ("`nBuilt {0} ({1:N1} MB)" -f $exe.FullName, ($exe.Length / 1MB))
