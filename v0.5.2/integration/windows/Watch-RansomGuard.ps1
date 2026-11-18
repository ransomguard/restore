$ErrorActionPreference = 'Stop'
$settings = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'installation.json') -Raw | ConvertFrom-Json
& $settings.python (Join-Path $PSScriptRoot 'Watch-RansomGuard.py') >> (Join-Path $PSScriptRoot 'supervisor-task.stdout.log') 2>> (Join-Path $PSScriptRoot 'supervisor-task.stderr.log')
exit $LASTEXITCODE
