# Extract Mordor partition → re-downsample → retrain. Skips re-labeling
# (Mordor was pre-labeled by _mordor-to-labeled-parquet.py).

$ErrorActionPreference = "Stop"
$env:PYTHONIOENCODING = "utf-8"
Set-Location "J:\THESIS-EDR\server\ml-engine\botsv2"

function Log($msg) {
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host "[$ts] $msg" -ForegroundColor Cyan
}

# Clean stale features for the new partition only.
Remove-Item -Recurse -Force "J:\THESIS-EDR\datasets\botsv2_features\sourcetype=mordor_sysmon" -ErrorAction SilentlyContinue

Log "=== STEP 1/4: extract_features.py --only mordor_sysmon ==="
python extract_features.py --only mordor_sysmon
if ($LASTEXITCODE -ne 0) { throw "extract_features failed" }

# downsample reads from botsv2_features_v2/ by default. Move our new sysmon
# partition into _v2 and run, then swap. But the existing pipeline expects
# the features dir to be intact. Simpler: change IN_DIR check or just symlink.
# Actually downsample.py reads from `botsv2_features`. We already have that.
# After extract_features --only writes to `botsv2_features_v2/`. Need to
# merge with botsv2_features OR force IN_DIR.
$src = "J:\THESIS-EDR\datasets\botsv2_features_v2\sourcetype=mordor_sysmon"
$dst = "J:\THESIS-EDR\datasets\botsv2_features\sourcetype=mordor_sysmon"
if (Test-Path $src) {
    Log "Moving $src -> $dst"
    if (Test-Path $dst) { Remove-Item -Recurse -Force $dst }
    Move-Item $src $dst
}

Log "=== STEP 2/4: downsample.py (rebuild splits) ==="
python downsample.py
if ($LASTEXITCODE -ne 0) { throw "downsample failed" }

Log "=== STEP 3/4: train stratified vanilla --tag no_st (drop sourcetype) ==="
python train.py --split stratified --drop-feature sourcetype --tag no_st --no-xt
if ($LASTEXITCODE -ne 0) { throw "train stratified vanilla failed" }

Log "=== STEP 4/4: train stratified XT --tag no_st (drop sourcetype) ==="
python train.py --split stratified --drop-feature sourcetype --tag no_st
if ($LASTEXITCODE -ne 0) { throw "train stratified XT failed" }

Log "ALL DONE."
