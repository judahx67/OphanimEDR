<#
.SYNOPSIS
    Ophanim EDR — full stack deployment script

.DESCRIPTION
    Brings up the EDR stack as Docker containers:
      rabbitmq, neo4j, pipeline, theia-gnn-scorer, theia-orthrus-scorer, api, dashboard

    Modes
    -----
    server   Start the full Docker stack, then tail all service logs (default)
    down     Stop and remove all containers

.PARAMETER Mode
    server | down

.PARAMETER Replay
    After starting, replay N DARPA TC E3 THEIA events through the pipeline.
    Requires the corpus at external/Flash-IDS. E.g.  -Replay 20000

.PARAMETER ReplayRate
    Replay events per second (default 500).

.PARAMETER RebuildImages
    Force docker compose build before starting.

.PARAMETER SkipHealthCheck
    Skip waiting for containers to become healthy.

.PARAMETER NoLogs
    Do not tail logs after startup (return to prompt immediately).

.EXAMPLE
    .\deploy\deploy.ps1                          # start stack + tail logs
    .\deploy\deploy.ps1 -Replay 20000            # start + replay data + tail logs
    .\deploy\deploy.ps1 -RebuildImages           # rebuild images then start
    .\deploy\deploy.ps1 -NoLogs                  # start without tailing logs
    .\deploy\deploy.ps1 -Mode down               # tear everything down
#>

param(
    [ValidateSet("server", "down")]
    [string]$Mode = "server",

    [int]$Replay = 0,
    [int]$ReplayRate = 500,
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

# --wait blocks until every service with a healthcheck reports healthy.
$waitFlag = if ($SkipHealthCheck) { @() } else { @("--wait", "--wait-timeout", "180") }
docker compose -f $ComposeFile up -d --remove-orphans @waitFlag

Write-Step "Service status:"
docker compose -f $ComposeFile ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

# ─────────────────────────────────────────────────────────────────────────────
# THEIA replay (optional)
# ─────────────────────────────────────────────────────────────────────────────

if ($Replay -gt 0) {
    $theiaDir = Join-Path $ProjectRoot "external\Flash-IDS"
    if (-not (Test-Path $theiaDir)) {
        Write-Warn "DARPA TC E3 THEIA corpus not found at:"
        Write-Warn "  $theiaDir"
        Write-Warn "Skipping replay. Place the corpus there and re-run with -Replay $Replay"
    } else {
        Write-Step "Replaying $Replay THEIA events at ${ReplayRate} events/sec..."
        Write-Info "(Runs in the foreground — Ctrl-C to stop early)"
        docker compose -f $ComposeFile --profile theia-sim run --rm theia-replay `
            --file  ta1-theia-e3-official-6r.json.8 `
            --limit $Replay `
            --rate  $ReplayRate
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
Write-Info ".\deploy\deploy.ps1 -Replay 20000"
Write-Host ""
Write-Host "  Stop everything" -ForegroundColor Yellow
Write-Info ".\deploy\deploy.ps1 -Mode down"
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# Live log tail
# ─────────────────────────────────────────────────────────────────────────────

if (-not $NoLogs) {
    Write-Host "  Tailing logs (Ctrl-C to stop)..." -ForegroundColor Yellow
    Write-Host "  Services: pipeline | theia-gnn-scorer | theia-orthrus-scorer | api" -ForegroundColor Gray
    Write-Host ""
    # docker compose logs --follow streams all services with colour-coded prefixes
    docker compose -f $ComposeFile logs --follow --tail 20 `
        pipeline theia-gnn-scorer theia-orthrus-scorer api
}
