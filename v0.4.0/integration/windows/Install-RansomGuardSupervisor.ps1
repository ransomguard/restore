$ErrorActionPreference = 'Stop'
$base = 'C:\RG_Test\Dashboard_Integration_20261116'
$python = 'C:\RG_Test\RansomGuard_RecoveryJEV_v0.4.0\.venv\Scripts\python.exe'
$startup = Get-ScheduledTask -TaskName 'RansomGuard-InteractiveStartup'
if ($startup.Principal.LogonType -ne 'Interactive') { throw 'Existing interactive startup principal required' }
$principal = New-ScheduledTaskPrincipal -UserId $startup.Principal.UserId -LogonType Interactive -RunLevel Highest
$exe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$action = New-ScheduledTaskAction -Execute $exe -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$base\Watch-RansomGuard.ps1`"" -WorkingDirectory $base
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(10) -RepetitionInterval (New-TimeSpan -Minutes 1)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'RansomGuard-PassiveSupervisor' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Observe-only collector exit recovery. No network listener, stored password, automatic UI reopening, process killing or firewall release.' -Force | Out-Null
Get-ScheduledTask -TaskName 'RansomGuard-PassiveSupervisor' | Select-Object TaskName,State,@{n='User';e={$_.Principal.UserId}},@{n='LogonType';e={$_.Principal.LogonType}} | ConvertTo-Json
