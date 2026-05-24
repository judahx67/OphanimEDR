# .crypt ransomware demo trigger for the live EDR closed-loop demo.
#
# Safe simulation: creates dummy .txt files in C:\demo\victim-docs\, then renames
# each to .crypt. This generates Sysmon EID=11 (FileCreate) events with the
# .crypt extension in TargetFilename, which the honest ML model fires on
# (probe score 0.88 vs 0.85 alert threshold).
#
# Requirements on the VPS:
#   - Sysmon installed with sysmon-modular config (EID=11 logged)
#   - Wazuh agent (or equivalent) forwarding Sysmon EVTX to our pipeline
#   - Defender exclusion configured for C:\demo\ (otherwise EICAR-like
#     heuristic may quarantine before Sysmon sees the writes)
#
# Usage from elevated PowerShell on the VPS:
#   powershell -ExecutionPolicy Bypass -File crypt-ransomware-trigger.ps1
#
# Demo flow:
#   1. Run this script.
#   2. ml-edge-scorer fires alert on each .crypt write (~5-20 alerts).
#   3. llm-analyzer reads the alert, generates a Sigma rule targeting .crypt
#      writes in TargetFilename.
#   4. Sigma rule pushed to Wazuh manager.
#   5. Re-run this script — Wazuh alerts directly via the new rule.

$VictimDir = "C:\demo\victim-docs"
$FileCount = 10

# Setup
if (-not (Test-Path $VictimDir)) {
    New-Item -ItemType Directory -Path $VictimDir -Force | Out-Null
}
Write-Host "[demo] Creating $FileCount dummy victim documents in $VictimDir"
for ($i = 1; $i -le $FileCount; $i++) {
    $name = "report_$i.txt"
    Set-Content -Path "$VictimDir\$name" -Value "Sensitive business document #$i. Replace before demo."
}

Start-Sleep -Seconds 2

# The "encryption" — rename to .crypt. Sysmon EID=11 fires on each create-target.
Write-Host "[demo] Simulating ransomware encryption (rename .txt -> .crypt)"
Get-ChildItem "$VictimDir\*.txt" | ForEach-Object {
    $cryptPath = "$($_.FullName).crypt"
    # Move-Item triggers a CloseHandle on the target = Sysmon FileCreate event
    Move-Item -Path $_.FullName -Destination $cryptPath -Force
    Write-Host "  encrypted: $($_.Name) -> $($_.Name).crypt"
    Start-Sleep -Milliseconds 300
}

Write-Host "[demo] Done. $FileCount .crypt files created. Check ml_alerts queue / Wazuh manager for alerts."
