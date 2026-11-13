# Detect Failed Logins

#log path
$logPath = ".\ProjectDataset\auth.log"
$failThreshold = 1

Write-Host " $ Starting Failed Login Detection $" -ForegroundColor Green
Write-Host ""

$hiCount = 0
$meCount = 0 
$loCount = 0

# Read log file
$lines = Get-Content $logPath

# Store IP attempt counts
$failedIPs = @{}

foreach ($line in $lines) {

    # Look for failed login attempts
    if ($line -match "Failed password") {

        # Extract IP address
        if ($line -match "from ([\d\.]+)") {

            $ip = $Matches[1]

            if ($failedIPs.ContainsKey($ip)) {
                $failedIPs[$ip]++
            }
            else {
                $failedIPs[$ip] = 1
            }
        }
    }
}

Write-Host " $ Scan completed $" -ForegroundColor Green 

# Print suspicious IPs
foreach ($ip in $failedIPs.Keys) {

    $attempts = $failedIPs[$ip]

    if ($failedIPs[$ip] -ge $failThreshold) {

        Write-Host "Suspicious IP Detected:" -ForegroundColor Blue
        Write-Host "IP Address: $ip"
        Write-Host "Failed Attempts: $attempts"

        # Risk levels based on amount of atetmpts 
        if ($attempts -ge 30) {
            Write-Host "Risk Level: HIGH" -ForegroundColor DarkRed
            $hiCount++
        }
        elseif ($attempts -ge 10) {
            Write-Host "Risk Level: MEDIUM" -ForegroundColor Yellow
            $meCount++
        }
        else { 
            Write-Host "Risk Level: LOW" -ForegroundColor Gray
            $loCount++
        }
        Write-Host "-------------------"
    }
}

# Brief summary
Write-Host ""
Write-Host "Brief Summary:" 
Write-Host "High Risk Count: $hiCount" -ForegroundColor red
Write-host "Medium Risk Count: $meCount" -ForegroundColor DarkYellow
Write-host "Low risk Count: $loCount" 
