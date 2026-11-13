# Detection Script for Suspicious Powershell

Write-Host "$ Starting Powershell Log Analysis $" -ForegroundColor Green

# log file path
$logPath = ".\ProjectDataset\powershell_log.txt"

# suspicous keywords
$keywords = @(
    "ExecutionPolicy Bypass",
    "EncodedCommand",
    "Invoke-WebRequest",
    "DownloadString",
    "Compress-Archive"
)

# store findings
$findings = @()

# read log file
$lines = Get-Content $logPath
foreach ($line in $lines) {

    foreach ($keyword in $keywords) {

        if ($line -match $keyword) {

            # extract timestamp
            $timestamp = ($line -split " ")[0..1] -join " "

            # create finding
            $finding = [PSCustomObject]@{
                Time = $timestamp
                Indicator = $keyword
                LogLine = $line
                Risk = "Possible risk"

            }

            $findings += $finding
        }
    }
}

# results

Write-host "$ Detection Complete $" -ForegroundColor Green

if ($findings.Count -eq 0) {

    Write-Host "No suspicious activity found." -ForegroundColor Green

} else {

    Write-host "--------"
    Write-Host "! Suspicious activity found !" -ForegroundColor DarkRed
    Write-host "--------"
    foreach ($finding in $findings) {

        Write-Host "Time: $($finding.Time)"
        Write-host "Indicatior: $($finding.Indicator)"
        Write-host "$($finding.Risk)" 
        Write-host "Log entry: $($finding.LogLine)" 
        Write-host "--------"
        
    }
}