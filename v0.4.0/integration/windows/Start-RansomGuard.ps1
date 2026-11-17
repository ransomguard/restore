$ErrorActionPreference='Stop'
$python='C:\RG_Test\RansomGuard_RecoveryJEV_v0.4.0\.venv\Scripts\python.exe'
$script='C:\RG_Test\Dashboard_Integration_20261116\Start-RansomGuard.py'
& $python $script
if($LASTEXITCODE -ne 0){throw 'Integrated startup failed'}
