$base = 'C:\RG_Test\Dashboard_Integration_20261116'
& 'C:\RG_Test\RansomGuard_RecoveryJEV_v0.4.0\.venv\Scripts\python.exe' "$base\Watch-RansomGuard.py" >> "$base\supervisor-task.stdout.log" 2>> "$base\supervisor-task.stderr.log"
exit $LASTEXITCODE
