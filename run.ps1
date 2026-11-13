# run.ps1 - Use to run all scripts
 
Write-Host "Starting Security Investigation Tool..." -ForegroundColor Green
 
. (Join-Path $PSScriptRoot "report.ps1")
 
Write-Host "Investigation Complete." -ForegroundColor Green