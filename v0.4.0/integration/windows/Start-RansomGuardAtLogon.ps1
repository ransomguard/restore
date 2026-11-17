$ErrorActionPreference = 'Stop'
$base = 'C:\RG_Test\Dashboard_Integration_20261116'
$python = 'C:\RG_Test\RansomGuard_RecoveryJEV_v0.4.0\.venv\Scripts\python.exe'
if ([Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { throw 'Dashboard requires an interactive user session' }
for ($attempt = 1; $attempt -le 6; $attempt++) {
    $ErrorActionPreference = 'Continue'
    & $python "$base\Start-RansomGuard.py" >> "$base\startup.stdout.log" 2>> "$base\startup.stderr.log"
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($code -eq 0) { exit 0 }
    Start-Sleep -Seconds 10
}
exit 1
