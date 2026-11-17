#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$TaskName = 'RansomGuard-HourlySnapshot')

$ErrorActionPreference = 'Stop'
if ($TaskName -notmatch '^RansomGuard-[A-Za-z0-9_-]+$') { throw 'Use a RansomGuard-prefixed task name.' }
$task = Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
if ($task.Description -notlike 'RansomGuard hourly VSS snapshot;*') {
    throw 'The task is not identified as this package snapshot task; no change was made.'
}
if ($task.State -eq 'Running') {
    throw 'A snapshot job is running. Wait for its result before removing its schedule.'
}
Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\' -Confirm:$false
Write-Output 'Schedule removed. Existing VSS snapshots, hourly state, and logs were retained.'
