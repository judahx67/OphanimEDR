<#
.SYNOPSIS
    Ophanim EDR build script

.DESCRIPTION
    Two targets:

    agent  (default)
        Builds the standalone edr_agent.exe via PyInstaller.

    docker
        Builds all Docker service images (api, ingest, graph-builder,
        rule-engine, simulator) without starting them.

    all
        Both of the above.

.PARAMETER Target
    agent | docker | all

.PARAMETER Clean
    agent target: remove dist/ and build/ before building.
    docker target: pass --no-cache to docker build.

.EXAMPLE
    .\scripts\build.ps1                   # build agent .exe
    .\scripts\build.ps1 -Target docker    # build docker images
    .\scripts\build.ps1 -Target all       # build both
    .\scripts\build.ps1 -Clean            # clean agent build
#>

param(
    [ValidateSet("agent", "docker", "all")]
    [string]$Target = "agent",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$ProjectRoot  = Split-Path -Parent $PSScriptRoot
$ComposeFile  = Join-Path $ProjectRoot "server\docker-compose.yml"

function Write-Header($Text) {
    Write-Host ""
    Write-Host ("=" * 56) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 56) -ForegroundColor Cyan
}

function Write-Step($Text) {
    Write-Host ""
    Write-Host ">> $Text" -ForegroundColor Green
}

function Write-Info($Text) {
    Write-Host "   $Text" -ForegroundColor Gray
}

function Require-Command($Name, $Hint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Write-Host "   ERROR: '$Name' not found. $Hint" -ForegroundColor Red
        exit 1
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Agent build
# ─────────────────────────────────────────────────────────────────────────────

function Build-Agent {
    Write-Header "Building EDR Agent executable"

    Require-Command "python" "Install Python 3.13+: https://www.python.org/"

    $venvDir = Join-Path $ProjectRoot "venv"
    $python  = if (Test-Path (Join-Path $venvDir "Scripts\python.exe")) {
        Join-Path $venvDir "Scripts\python.exe"
    } else {
        "python"
    }

    Push-Location $ProjectRoot
    try {
        if ($Clean) {
            Write-Step "Cleaning previous build artifacts..."
            Remove-Item -Path "dist"  -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "build" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "*.spec" -Force  -ErrorAction SilentlyContinue
            Write-Info "Cleaned."
        }

        Write-Step "Checking PyInstaller..."
        $installed = & $python -m pip show pyinstaller 2>$null
        if (-not $installed) {
            Write-Info "Installing PyInstaller..."
            & $python -m pip install pyinstaller --quiet
        } else {
            Write-Info "PyInstaller already installed"
        }

        Write-Step "Running PyInstaller..."
        & $python -m PyInstaller `
            --name "edr_agent" `
            --onefile `
            --console `
            --clean `
            --noconfirm `
            --paths "agent\src" `
            --add-data ".env;." `
            --hidden-import "win32evtlog" `
            --hidden-import "win32evtlogutil" `
            --hidden-import "watchdog.observers" `
            --hidden-import "watchdog.events" `
            --collect-submodules "edr_agent" `
            agent\src\edr_agent\__main__.py

        if (Test-Path "dist\edr_agent.exe") {
            $sizeMB = [math]::Round((Get-Item "dist\edr_agent.exe").Length / 1MB, 2)
            Write-Host ""
            Write-Host "   Build successful: dist\edr_agent.exe ($sizeMB MB)" -ForegroundColor Green
            Write-Host "   Run with: .\dist\edr_agent.exe" -ForegroundColor Cyan
        } else {
            Write-Host "   ERROR: executable not found — PyInstaller may have failed" -ForegroundColor Red
            exit 1
        }
    } finally {
        Pop-Location
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Docker image build
# ─────────────────────────────────────────────────────────────────────────────

function Build-Docker {
    Write-Header "Building Docker service images"

    Require-Command "docker" "Install Docker Desktop: https://docs.docker.com/get-docker/"

    $cacheFlag = if ($Clean) { "--no-cache" } else { "" }

    Write-Step "Building images via docker compose..."
    Write-Info "Services: api, ingest, graph-builder, rule-engine, simulator"
    Write-Info "(simulator is excluded from default 'up' but built here for completeness)"

    if ($cacheFlag) {
        docker compose -f $ComposeFile build --no-cache
    } else {
        docker compose -f $ComposeFile build
    }

    Write-Host ""
    Write-Host "   All images built successfully." -ForegroundColor Green
    Write-Host "   Start the stack with:" -ForegroundColor Cyan
    Write-Host "     .\scripts\deploy.ps1" -ForegroundColor Cyan
}

# ─────────────────────────────────────────────────────────────────────────────
# Dispatch
# ─────────────────────────────────────────────────────────────────────────────

switch ($Target) {
    "agent"  { Build-Agent }
    "docker" { Build-Docker }
    "all"    { Build-Agent; Build-Docker }
}

Write-Host ""
