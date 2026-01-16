<#
.SYNOPSIS
    Ophanim EDR Development Stack Deployment Script

.DESCRIPTION
    Sets up the complete EDR development environment including:
    - Python virtual environment
    - Agent dependencies
    - MongoDB (via Docker)
    - Environment configuration

.PARAMETER Mode
    Deployment mode: 'dev' (default), 'agent-only', 'server-only', 'full'

.PARAMETER ServerUrl
    Management server URL for agent configuration

.PARAMETER SkipDocker
    Skip Docker/MongoDB setup

.EXAMPLE
    .\deploy.ps1 -Mode dev
    .\deploy.ps1 -Mode agent-only -SkipDocker
#>

param(
    [ValidateSet("dev", "agent-only", "server-only", "full")]
    [string]$Mode = "dev",
    
    [string]$ServerUrl = "http://localhost:8000",
    
    [switch]$SkipDocker,
    
    [switch]$SkipVenv
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Ophanim EDR Deployment Script" -ForegroundColor Cyan
Write-Host "  Mode: $Mode" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

function Test-Command($Command) {
    return [bool](Get-Command -Name $Command -ErrorAction SilentlyContinue)
}

function Write-Step($Message) {
    Write-Host "`n[$([DateTime]::Now.ToString('HH:mm:ss'))] $Message" -ForegroundColor Green
}

function Write-Warning($Message) {
    Write-Host "  WARNING: $Message" -ForegroundColor Yellow
}

function Write-Error($Message) {
    Write-Host "  ERROR: $Message" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# Prerequisites Check
# -----------------------------------------------------------------------------

Write-Step "Checking prerequisites..."

# Python
if (-not (Test-Command "python")) {
    Write-Error "Python not found. Please install Python 3.13+"
    exit 1
}

$pythonVersion = python --version 2>&1
Write-Host "  Found: $pythonVersion"

# Docker (optional)
if (-not $SkipDocker) {
    if (Test-Command "docker") {
        $dockerVersion = docker --version 2>&1
        Write-Host "  Found: $dockerVersion"
    } else {
        Write-Warning "Docker not found. Use -SkipDocker to skip container setup."
        $SkipDocker = $true
    }
}

# -----------------------------------------------------------------------------
# Virtual Environment Setup
# -----------------------------------------------------------------------------

if (-not $SkipVenv) {
    Write-Step "Setting up Python virtual environment..."
    
    $venvPath = Join-Path $ProjectRoot "venv"
    
    if (-not (Test-Path $venvPath)) {
        Write-Host "  Creating virtual environment..."
        python -m venv $venvPath
    } else {
        Write-Host "  Virtual environment already exists"
    }
    
    # Activate venv
    $activateScript = Join-Path $venvPath "Scripts\Activate.ps1"
    if (Test-Path $activateScript) {
        Write-Host "  Activating virtual environment..."
        & $activateScript
    }
    
    # Upgrade pip
    Write-Host "  Upgrading pip..."
    python -m pip install --upgrade pip -q
}

# -----------------------------------------------------------------------------
# Install Dependencies
# -----------------------------------------------------------------------------

Write-Step "Installing dependencies..."

Push-Location $ProjectRoot
try {
    switch ($Mode) {
        "agent-only" {
            Write-Host "  Installing agent dependencies..."
            pip install -e "." -q
        }
        "server-only" {
            Write-Host "  Installing server dependencies..."
            pip install -e ".[server]" -q
        }
        default {
            Write-Host "  Installing all dependencies (dev mode)..."
            pip install -e ".[dev,server]" -q
        }
    }
    Write-Host "  Dependencies installed successfully"
} finally {
    Pop-Location
}

# -----------------------------------------------------------------------------
# Docker Services (MongoDB)
# -----------------------------------------------------------------------------

if (-not $SkipDocker -and ($Mode -eq "dev" -or $Mode -eq "server-only" -or $Mode -eq "full")) {
    Write-Step "Setting up Docker services..."
    
    # Check if MongoDB container exists
    $mongoContainer = docker ps -a --filter "name=ophanim-mongo" --format "{{.Names}}" 2>$null
    
    if ($mongoContainer -eq "ophanim-mongo") {
        $mongoStatus = docker inspect --format "{{.State.Running}}" ophanim-mongo 2>$null
        if ($mongoStatus -eq "true") {
            Write-Host "  MongoDB container already running"
        } else {
            Write-Host "  Starting existing MongoDB container..."
            docker start ophanim-mongo
        }
    } else {
        Write-Host "  Creating MongoDB container..."
        docker run -d `
            --name ophanim-mongo `
            -p 27017:27017 `
            -v ophanim-mongo-data:/data/db `
            -e MONGO_INITDB_DATABASE=ophanim_edr `
            mongo:7
        
        Write-Host "  MongoDB container created and started"
    }
    
    # Wait for MongoDB to be ready
    Write-Host "  Waiting for MongoDB to be ready..."
    $attempts = 0
    $maxAttempts = 30
    while ($attempts -lt $maxAttempts) {
        $result = docker exec ophanim-mongo mongosh --eval "db.runCommand('ping').ok" --quiet 2>$null
        if ($result -eq "1") {
            Write-Host "  MongoDB is ready"
            break
        }
        Start-Sleep -Seconds 1
        $attempts++
    }
    
    if ($attempts -eq $maxAttempts) {
        Write-Warning "MongoDB may not be fully ready yet"
    }
}

# -----------------------------------------------------------------------------
# Environment Configuration
# -----------------------------------------------------------------------------

Write-Step "Configuring environment..."

# Create .env file if it doesn't exist
$envFile = Join-Path $ProjectRoot ".env"
if (-not (Test-Path $envFile)) {
    $envContent = @"
# Ophanim EDR Configuration
# Generated by deploy.ps1 on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

# Agent Configuration
EDR_ENDPOINT_ID=$env:COMPUTERNAME
SERVER_URL=$ServerUrl
AGENT_API_KEY=dev-api-key-change-in-production
LOG_LEVEL=DEBUG
PROCESS_POLL_INTERVAL=2.0

# Server Configuration
MONGODB_URL=mongodb://localhost:27017
DATABASE_NAME=ophanim_edr

# Sysmon (set to false if Sysmon not installed)
SYSMON_ENABLED=false
FILESYSTEM_ENABLED=true
"@
    
    $envContent | Out-File -FilePath $envFile -Encoding UTF8
    Write-Host "  Created .env file"
} else {
    Write-Host "  .env file already exists"
}

# Create logs directory
$logsDir = Join-Path $ProjectRoot "logs"
if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir | Out-Null
    Write-Host "  Created logs directory"
}

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Deployment Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow

if ($Mode -eq "dev" -or $Mode -eq "agent-only" -or $Mode -eq "full") {
    Write-Host "  Run the agent:" -ForegroundColor White
    Write-Host "    .\venv\Scripts\Activate.ps1" -ForegroundColor Gray
    Write-Host "    python -m edr_agent" -ForegroundColor Gray
    Write-Host ""
}

if (-not $SkipDocker -and ($Mode -eq "dev" -or $Mode -eq "server-only" -or $Mode -eq "full")) {
    Write-Host "  MongoDB is running on:" -ForegroundColor White
    Write-Host "    mongodb://localhost:27017" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Stop MongoDB:" -ForegroundColor White
    Write-Host "    docker stop ophanim-mongo" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Configuration file: $envFile" -ForegroundColor Gray
Write-Host ""
