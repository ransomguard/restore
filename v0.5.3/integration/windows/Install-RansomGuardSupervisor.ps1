# Optional: run only after a successful manual start INSIDE the test VM.
$ErrorActionPreference = 'Stop'
$base = $PSScriptRoot
if (-not (Test-Path -LiteralPath (Join-Path $base 'installation.json'))) { throw 'Configure the runtime first' }
foreach ($name in @('RansomGuard-InteractiveStartup', 'RansomGuard-PassiveSupervisor')) {
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { throw "Task already exists; preserve its configuration: $name" }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Highest
$exe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$startup = New-ScheduledTaskAction -Execute $exe -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$base\Start-RansomGuardAtLogon.ps1`"" -WorkingDirectory $base
$atLogon = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
Register-ScheduledTask -TaskName 'RansomGuard-InteractiveStartup' -Action $startup -Trigger $atLogon -Principal $principal -Settings $settings -Description 'RansomGuard startup in the logged-on VM user session; no stored password.' | Out-Null
$action = New-ScheduledTaskAction -Execute $exe -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$base\Watch-RansomGuard.ps1`"" -WorkingDirectory $base
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'RansomGuard-PassiveSupervisor' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Bounded collector health check; no listener, password, process killing or hold release.' | Out-Null
Write-Output 'Tasks registered. They require a logged-on interactive user; this does not enable Windows automatic login.'
