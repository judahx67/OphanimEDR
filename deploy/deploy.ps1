<#
.SYNOPSIS
    Ophanim EDR — full stack deployment script

.DESCRIPTION
    Brings up every component of the EDR system as Docker containers:
      rabbitmq, neo4j, ingest, graph-builder, rule-engine, api, dashboard

    Modes
    -----
    server   Start the full Docker stack, then tail all service logs (default)
    down     Stop and remove all containers

    The EDR agent is out of scope for this script — it will be revamped separately.

.PARAMETER Mode
    server | down

.PARAMETER Replay
    After starting, replay N THEIA events through the pipeline.
    E.g.  -Replay 30000

.PARAMETER ReplayRate
    Simulator events per second (default 2000).

.PARAMETER RebuildImages
    Force docker compose build before starting.

.PARAMETER SkipHealthCheck
    Skip waiting for containers to become healthy.

.PARAMETER NoLogs
    Do not tail logs after startup (return to prompt immediately).

.EXAMPLE
    .\scripts\deploy.ps1                          # start stack + tail logs
    .\scripts\deploy.ps1 -Replay 30000            # start + replay data + tail logs
    .\scripts\deploy.ps1 -RebuildImages           # rebuild images then start
    .\scripts\deploy.ps1 -NoLogs                  # start without tailing logs
    .\scripts\deploy.ps1 -Mode down               # tear everything down
#>

param(
    [ValidateSet("server", "down")]
    [string]$Mode = "server",

    [int]$Replay = 0,
    [int]$ReplayRate = 2000,
    [switch]$RebuildImages,
    [switch]$SkipHealthCheck,
    [switch]$NoLogs
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ComposeFile = Join-Path $ProjectRoot "server\docker-compose.yml"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

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

function Write-Warn($Text) {
    Write-Host "   WARN: $Text" -ForegroundColor Yellow
}

function Require-Command($Name, $Hint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Write-Host "   ERROR: '$Name' not found. $Hint" -ForegroundColor Red
        exit 1
    }
}

function Wait-ServiceHealthy($ContainerName, $MaxSeconds = 90) {
    Write-Info "Waiting for $ContainerName..."
    $elapsed = 0
    while ($elapsed -lt $MaxSeconds) {
        $health  = docker inspect --format "{{.State.Health.Status}}" $ContainerName 2>$null
        $running = docker inspect --format "{{.State.Running}}"       $ContainerName 2>$null
        if ($health -eq "healthy") {
            Write-Info "$ContainerName  [healthy]"
            return
        }
        if ($running -eq "true" -and ($health -eq "" -or $health -eq $null)) {
            Write-Info "$ContainerName  [running]"
            return
        }
        Start-Sleep -Seconds 3
        $elapsed += 3
    }
    Write-Warn "$ContainerName did not become healthy within ${MaxSeconds}s — continuing"
}

# ─────────────────────────────────────────────────────────────────────────────
# Mode: down
# ─────────────────────────────────────────────────────────────────────────────

if ($Mode -eq "down") {
    Write-Header "Ophanim EDR — Stopping Stack"
    Require-Command "docker" "Install Docker Desktop: https://docs.docker.com/get-docker/"
    Write-Step "Stopping and removing containers..."
    docker compose -f $ComposeFile down --remove-orphans
    Write-Host ""
    Write-Host "   Stack stopped." -ForegroundColor Green
    exit 0
}

# ─────────────────────────────────────────────────────────────────────────────
# Prerequisites
# ─────────────────────────────────────────────────────────────────────────────

Write-Header "Ophanim EDR  [mode: $Mode]"
Write-Info "Project root : $ProjectRoot"
Write-Info "Compose file : $ComposeFile"

Write-Step "Checking prerequisites..."
Require-Command "docker" "Install Docker Desktop: https://docs.docker.com/get-docker/"
Write-Info "Docker : $(docker --version)"

# ─────────────────────────────────────────────────────────────────────────────
# Docker stack
# ─────────────────────────────────────────────────────────────────────────────

Write-Step "Starting Docker services..."

if ($RebuildImages) {
    Write-Info "Rebuilding images (--build)..."
    docker compose -f $ComposeFile build
}

docker compose -f $ComposeFile up -d --remove-orphans

if (-not $SkipHealthCheck) {
    Write-Step "Waiting for services..."
    Wait-ServiceHealthy "edr-rabbitmq"      90
    Wait-ServiceHealthy "edr-neo4j"         90
    Wait-ServiceHealthy "edr-ingest"        45
    Wait-ServiceHealthy "edr-graph-builder" 45
    Wait-ServiceHealthy "edr-rule-engine"   45
    Wait-ServiceHealthy "edr-api"           45
    Wait-ServiceHealthy "edr-dashboard"     60
}

Write-Step "Service status:"
docker compose -f $ComposeFile ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

# ─────────────────────────────────────────────────────────────────────────────
# THEIA replay (optional)
# ─────────────────────────────────────────────────────────────────────────────

if ($Replay -gt 0) {
    $theiaFile = Join-Path $ProjectRoot "darpa_data\data\theia\ta1-theia-e3-official-1r.json.0"
    if (-not (Test-Path $theiaFile)) {
        Write-Warn "DARPA THEIA file not found at:"
        Write-Warn "  $theiaFile"
        Write-Warn "Skipping replay. Place the dataset there and re-run with -Replay $Replay"
    } else {
        Write-Step "Replaying $Replay THEIA events at ${ReplayRate} events/sec..."
        Write-Info "(Runs in the foreground — Ctrl-C to stop early)"
        docker compose -f $ComposeFile --profile simulator run --rm simulator `
            --scenario theia `
            --limit    $Replay `
            --rate     $ReplayRate
        Write-Step "Replay complete."
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────

Write-Header "Deployment complete"
Write-Host ""
Write-Host "  Endpoints" -ForegroundColor Yellow
Write-Info "Dashboard      http://localhost:3000"
Write-Info "API / Swagger  http://localhost:8000/docs"
Write-Info "Neo4j Browser  http://localhost:7474   (neo4j / edr-thesis)"
Write-Info "RabbitMQ Admin http://localhost:15672  (guest / guest)"
Write-Host ""
Write-Host "  Replay THEIA data" -ForegroundColor Yellow
Write-Info ".\scripts\deploy.ps1 -Replay 30000"
Write-Host ""
Write-Host "  Stop everything" -ForegroundColor Yellow
Write-Info ".\scripts\deploy.ps1 -Mode down"
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# Live log tail
# ─────────────────────────────────────────────────────────────────────────────

if (-not $NoLogs) {
    Write-Host "  Tailing logs (Ctrl-C to stop)..." -ForegroundColor Yellow
    Write-Host "  Services: ingest | graph-builder | rule-engine | api" -ForegroundColor Gray
    Write-Host ""
    # docker compose logs --follow streams all services with colour-coded prefixes
    docker compose -f $ComposeFile logs --follow --tail 20 `
        ingest graph-builder rule-engine api
}
