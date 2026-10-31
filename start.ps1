$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$AgentShieldPython = Join-Path $PSScriptRoot 'venv\Scripts\pythonw.exe'
if (Test-Path -LiteralPath $AgentShieldPython) {
    Start-Process -FilePath $AgentShieldPython -ArgumentList 'dashboard.py' -WorkingDirectory $PSScriptRoot -WindowStyle Hidden
} else {
    python dashboard.py
}
