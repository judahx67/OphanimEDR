<#
.SYNOPSIS
    Build EDR Agent executable using PyInstaller

.DESCRIPTION
    Creates a standalone .exe for the EDR Agent using PyInstaller.
    Much faster for development iteration than pip install.

.PARAMETER Clean
    Remove previous build artifacts before building

.EXAMPLE
    .\scripts\build.ps1
    .\scripts\build.ps1 -Clean
#>

param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Ophanim EDR Agent Build" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

Push-Location $ProjectRoot
try {
    # Clean previous builds
    if ($Clean) {
        Write-Host "`nCleaning previous builds..." -ForegroundColor Yellow
        Remove-Item -Path "dist" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "build" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "*.spec" -Force -ErrorAction SilentlyContinue
    }

    # Ensure PyInstaller is installed
    Write-Host "`nChecking PyInstaller..." -ForegroundColor Green
    $pyinstaller = .\venv\Scripts\pip.exe show pyinstaller 2>$null
    if (-not $pyinstaller) {
        Write-Host "Installing PyInstaller..." -ForegroundColor Yellow
        .\venv\Scripts\pip.exe install pyinstaller --quiet
    }

    # Build the executable
    Write-Host "`nBuilding executable..." -ForegroundColor Green
    .\venv\Scripts\pyinstaller.exe `
        --name "edr_agent" `
        --onefile `
        --console `
        --clean `
        --noconfirm `
        --add-data ".env;." `
        --hidden-import "win32evtlog" `
        --hidden-import "win32evtlogutil" `
        --hidden-import "watchdog.observers" `
        --hidden-import "watchdog.events" `
        --collect-submodules "edr_agent" `
        agent\src\edr_agent\__main__.py

    # Check result
    if (Test-Path "dist\edr_agent.exe") {
        $size = (Get-Item "dist\edr_agent.exe").Length / 1MB
        Write-Host "`n============================================" -ForegroundColor Green
        Write-Host "  Build successful!" -ForegroundColor Green
        Write-Host "  Output: dist\edr_agent.exe ($([math]::Round($size, 2)) MB)" -ForegroundColor Green
        Write-Host "============================================" -ForegroundColor Green
        Write-Host "`nRun with: .\dist\edr_agent.exe" -ForegroundColor Cyan
    } else {
        Write-Host "`nBuild failed - executable not found" -ForegroundColor Red
        exit 1
    }

} finally {
    Pop-Location
}
