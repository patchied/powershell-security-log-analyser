# Generate security report

param ([string]$OutputDir = ".\Reports")

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

$timestamp  = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportFile = Join-Path $OutputDir "SecurityReport_$timestamp.txt"
$report     = @()

# Run all 3 scripts and capture their results
foreach ($script in @("fail.ps1", "ps.ps1", "ioc.ps1")) {
    Write-Host "[*] Running $script ..." -ForegroundColor Green
    . (Join-Path $PSScriptRoot $script) 6>$null
}

# Header message
$report += "===================================="
$report += "  SECURITY REPORT - $timestamp"
$report += "===================================="
$report += ""

# Failed Logins
$report += "[ FAILED LOGINS ]"
foreach ($ip in $failedIPs.Keys | Sort-Object) {
    $attempts = $failedIPs[$ip]
    $risk = if ($attempts -ge 30) { "HIGH" } elseif ($attempts -ge 10) { "MEDIUM" } else { "LOW" }
    $report += "  $ip | Attempts: $attempts | Risk: $risk"
}
$report += ""

# Suspicious PowerShell
$report += "[ SUSPICIOUS POWERSHELL ]"
foreach ($f in $findings) {
    $report += "  $($f.Time) | $($f.Indicator) | $($f.Risk)"
}
$report += ""

# Section 3 - IOC Matches
$report += "[ IOC MATCHES ]"
foreach ($m in $matched) {
    $report += "  $($m.Indicator) | Risk: $($m.Risk) | $($m.LogEntry)"
}
$report += ""

# Summary
$report += "===================================="
$report += "  SUMMARY"
$report += "  Failed Login IPs : $($failedIPs.Count)"
$report += "  PS Findings      : $($findings.Count)"
$report += "  IOC Matches      : $($matched.Count)"
$report += "===================================="

$report | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "`n$ Report saved: $reportFile $" -ForegroundColor Green