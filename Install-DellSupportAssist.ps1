# Download and install Dell SupportAssist silently
Write-Host "Downloading Dell SupportAssist..."
Invoke-WebRequest -Uri "https://downloads.dell.com/serviceability/catalog/SupportAssistInstaller.exe" -OutFile "$env:TEMP\SupportAssistInstaller.exe"
Write-Host "Installing Dell SupportAssist (silent)..."
Start-Process "$env:TEMP\SupportAssistInstaller.exe" -ArgumentList '/s /v"/qn"' -Wait
Write-Host "Dell SupportAssist installation complete." -ForegroundColor Green
