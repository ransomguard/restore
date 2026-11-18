$ErrorActionPreference = 'Stop'
$settings = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'installation.json') -Raw | ConvertFrom-Json
& $settings.python (Join-Path $PSScriptRoot 'Start-RansomGuard.py')
if ($LASTEXITCODE -ne 0) { throw 'Integrated startup failed' }
