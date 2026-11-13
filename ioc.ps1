# Detect IOC Matches
$logPath = ".\ProjectDataset\access.log"
$iocPath = ".\ProjectDataset\ioc.txt"

Write-Host "$ Starting IOC Detection $" -ForegroundColor Green


$logLines = Get-Content $logPath
$iocs = Get-Content $iocPath
$matched = @()

Write-Host "Reading $($logLines.Count) log entries..." -ForegroundColor Green

# Loop through lines
foreach ($line in $logLines) {
    foreach ($ioc in $iocs) {
        # Skip empty lines 
        if ([string]::IsNullOrWhiteSpace($ioc)) { continue }

        # Use -match to catch suspicous activity
        if ($line -match [regex]::Escape($ioc.Trim())) {
            $match = [PSCustomObject]@{
                Indicator = $ioc.Trim()
                LogEntry  = $line
                Risk      = "HIGH"
            }
            $matched += $match
        }
    }
}

# Output Results
Write-Host "$ Scan complete. $ " -ForegroundColor Green


if ($matched.Count -eq 0) {
    Write-Host "No IOC matches found." -ForegroundColor Green
} else {
    Write-Host "! IOC Matches Detected ! " -ForegroundColor DarkRed
    Write-Host "! $($matched.Count) found !" -ForegroundColor DarkRed
    Write-Host "---------------"
    foreach ($m in $matched) {
        Write-Host "Indicator: $($m.Indicator)"
        Write-Host "Log Entry: $($m.LogEntry)"
        Write-Host "Risk Level: $($m.Risk)"
        Write-Host "---------"
    }
}