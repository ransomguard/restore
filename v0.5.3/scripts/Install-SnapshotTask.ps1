#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PythonPath,
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\config\example.json'),
    [string]$StateDirectory = (Join-Path $env:ProgramData 'RansomGuard'),
    [string]$TaskName = 'RansomGuard-HourlySnapshot'
)

$ErrorActionPreference = 'Stop'
if ($TaskName -notmatch '^RansomGuard-[A-Za-z0-9_-]+$') { throw 'Use a RansomGuard-prefixed task name.' }
$python = (Resolve-Path -LiteralPath $PythonPath).ProviderPath
$config = (Resolve-Path -LiteralPath $ConfigPath).ProviderPath
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'PythonPath must identify an installed Python executable.' }
if (-not [IO.Path]::IsPathRooted($StateDirectory)) { throw 'StateDirectory must be absolute.' }
if (Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue) {
    throw 'This task already exists. Inspect it or use Uninstall-SnapshotTask.ps1 before registering a replacement.'
}

# Creates directories and a task definition only. It does not create a snapshot.
New-Item -ItemType Directory -Path $StateDirectory -Force | Out-Null
$stateRoot = (Resolve-Path -LiteralPath $StateDirectory).ProviderPath
$snapshotState = Join-Path $stateRoot 'snapshots.sqlite3'
$eventOutbox = Join-Path $stateRoot 'events.sqlite3'
$taskXmlPath = Join-Path $stateRoot ($TaskName + '.xml')
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

& $python -I -m ransomguard snapshot-task --config $config --python-executable $python --state-db $snapshotState --db $eventOutbox --user-sid $sid --output $taskXmlPath
if ($LASTEXITCODE -ne 0) { throw 'Task definition generation failed; no scheduled task was installed.' }
$taskXml = Get-Content -LiteralPath $taskXmlPath -Raw -Encoding UTF8
$registered = Register-ScheduledTask -TaskName $TaskName -TaskPath '\' -Xml $taskXml
$info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath '\'
[pscustomobject]@{
    TaskName = $registered.TaskName
    NextRunTime = $info.NextRunTime
    IntervalSeconds = 3600
    RunContext = 'Current administrator; only while logged on'
    SnapshotCreatedDuringInstall = $false
    StateDatabase = $snapshotState
    OutboxDatabase = $eventOutbox
    TaskDefinition = $taskXmlPath
} | Format-List
