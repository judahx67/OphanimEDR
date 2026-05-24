# Re-label → re-extract → re-downsample → re-train both honest models.
# Output renames preserve any prior dataset under _260524 suffix.

$ErrorActionPreference = "Stop"
$env:PYTHONIOENCODING = "utf-8"

Set-Location "J:\THESIS-EDR\server\ml-engine\botsv2"

function Log($msg) {
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host "[$ts] $msg" -ForegroundColor Cyan
}

# Wipe any prior incomplete _v2 dirs so resume-guards in label.py /
# extract_features.py don't pick up half-written partitions.
foreach ($p in @("J:\THESIS-EDR\datasets\botsv2_labeled_v2",
                 "J:\THESIS-EDR\datasets\botsv2_features_v2")) {
    if (Test-Path $p) {
        Log "Removing stale $p"
        Remove-Item -Recurse -Force $p
    }
}

Log "=== STEP 1/5: label.py ==="
python label.py
if ($LASTEXITCODE -ne 0) { throw "label.py failed" }

Log "=== STEP 1.5: swap labeled directories ==="
if (Test-Path "J:\THESIS-EDR\datasets\botsv2_labeled_260524") {
    Remove-Item -Recurse -Force "J:\THESIS-EDR\datasets\botsv2_labeled_260524"
}
Rename-Item "J:\THESIS-EDR\datasets\botsv2_labeled" "botsv2_labeled_260524"
Rename-Item "J:\THESIS-EDR\datasets\botsv2_labeled_v2" "botsv2_labeled"

Log "=== STEP 2/5: extract_features.py ==="
python extract_features.py
if ($LASTEXITCODE -ne 0) { throw "extract_features.py failed" }

Log "=== STEP 2.5: swap features directories ==="
if (Test-Path "J:\THESIS-EDR\datasets\botsv2_features_260524") {
    Remove-Item -Recurse -Force "J:\THESIS-EDR\datasets\botsv2_features_260524"
}
Rename-Item "J:\THESIS-EDR\datasets\botsv2_features" "botsv2_features_260524"
Rename-Item "J:\THESIS-EDR\datasets\botsv2_features_v2" "botsv2_features"

Log "=== STEP 3/5: downsample.py ==="
python downsample.py
if ($LASTEXITCODE -ne 0) { throw "downsample.py failed" }

Log "=== STEP 3.5: backup existing honest model dirs ==="
foreach ($m in @("lgbm_xt_temporal_no_st", "lgbm_xt_stratified_no_st")) {
    $src = "models\$m"
    $dst = "models\${m}_pre_relabel_260524"
    if ((Test-Path $src) -and -not (Test-Path $dst)) {
        Log "Backing up $src -> $dst"
        Copy-Item -Recurse -Path $src -Destination $dst
    }
}

Log "=== STEP 4/5: train temporal --tag no_st (drop sourcetype) ==="
python train.py --split temporal --drop-feature sourcetype --tag no_st
if ($LASTEXITCODE -ne 0) { throw "train temporal failed" }

Log "=== STEP 5/5: train stratified --tag no_st (drop sourcetype) ==="
python train.py --split stratified --drop-feature sourcetype --tag no_st
if ($LASTEXITCODE -ne 0) { throw "train stratified failed" }

Log "ALL DONE. Models written under models/."
