# Read-only environment inventory. Run INSIDE the Windows development/test VM.
# Does not install packages, change boot settings, create VSS snapshots, or reveal API/proxy secrets.
[CmdletBinding()]
param([string]$OutputPath = "")
$ErrorActionPreference = "Stop"
$RansomGuardReport = [ordered]@{
    collected_at_utc = [DateTime]::UtcNow.ToString("o")
    scope_note = "Versions belong to the machine running this script; run in the VM if it builds/runs RansomGuard."
}
try {
    $RansomGuardOs = Get-CimInstance -ClassName Win32_OperatingSystem
    $RansomGuardMachine = Get-CimInstance -ClassName Win32_ComputerSystem
    $RansomGuardReport.windows = [ordered]@{
        caption = $RansomGuardOs.Caption
        version = $RansomGuardOs.Version
        build = $RansomGuardOs.BuildNumber
        architecture = $RansomGuardOs.OSArchitecture
        manufacturer = $RansomGuardMachine.Manufacturer
        model = $RansomGuardMachine.Model
        memory_gib = [Math]::Round($RansomGuardMachine.TotalPhysicalMemory / 1GB, 1)
    }
} catch { $RansomGuardReport.windows_error = $_.Exception.Message }

$RansomGuardVswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path -LiteralPath $RansomGuardVswhere) {
    try {
        $RansomGuardVs = & $RansomGuardVswhere -all -products '*' -format json | ConvertFrom-Json
        $RansomGuardReport.visual_studio = @($RansomGuardVs | ForEach-Object {
            [ordered]@{ name = $_.displayName; version = $_.installationVersion; path = $_.installationPath }
        })
    } catch { $RansomGuardReport.visual_studio_error = $_.Exception.Message }
} else { $RansomGuardReport.visual_studio = @(); $RansomGuardReport.visual_studio_note = "vswhere.exe not found" }

$RansomGuardUninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$RansomGuardReport.kit_registered_products = @(
    Get-ItemProperty $RansomGuardUninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'Windows.*(Driver Kit|Software Development Kit|SDK|WDK)' } |
        Select-Object DisplayName, DisplayVersion -Unique
)
$RansomGuardKitInclude = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Include'
$RansomGuardReport.kit_header_directories = @()
if (Test-Path -LiteralPath $RansomGuardKitInclude) {
    $RansomGuardReport.kit_header_directories = @(Get-ChildItem -LiteralPath $RansomGuardKitInclude -Directory | ForEach-Object {
        [ordered]@{
            version_directory = $_.Name
            has_wdk_kernel_headers = Test-Path -LiteralPath (Join-Path $_.FullName 'km\ntddk.h')
            has_sdk_user_headers = Test-Path -LiteralPath (Join-Path $_.FullName 'um\Windows.h')
        }
    })
}
$RansomGuardReport.kit_version_note = "Header directory names identify the kit build; .0 does not prove the installed QFE. Use registered product versions above."

$RansomGuardPython = Get-Command python.exe -ErrorAction SilentlyContinue
if ($RansomGuardPython) {
    $RansomGuardPythonCode = @'
import importlib.metadata as m, json, os, platform, sys
def version(name):
    try:
        return m.version(name)
    except m.PackageNotFoundError:
        return None
print(json.dumps({"executable":sys.executable,"version":platform.python_version(),"architecture":platform.architecture()[0],"typesafe_sdk":version("typesafe-sdk"),"python_dotenv":version("python-dotenv"),"typesafe_base_url_override_present":bool(os.environ.get("TYPESAFE_BASE_URL")),"typesafe_api_key_present":bool(os.environ.get("TYPESAFE_API_KEY")),"proxy_environment_present":{k:bool(os.environ.get(k)) for k in ("HTTPS_PROXY","HTTP_PROXY","ALL_PROXY","https_proxy","http_proxy","all_proxy")}}))
'@
    try {
        $RansomGuardPythonJson = & $RansomGuardPython.Source -c $RansomGuardPythonCode
        if ($LASTEXITCODE -eq 0) { $RansomGuardReport.python = $RansomGuardPythonJson | ConvertFrom-Json }
        else { $RansomGuardReport.python_error = "python.exe returned a nonzero exit code" }
    } catch { $RansomGuardReport.python_error = $_.Exception.Message }
} else { $RansomGuardReport.python_note = "python.exe not found in PATH; activate the intended virtual environment and rerun" }
$RansomGuardReport.wmic_present = [bool](Get-Command wmic.exe -ErrorAction SilentlyContinue)
$RansomGuardReport.proxy_note = "Only presence flags are collected. Proxy URL credentials and API key values are never printed."
$RansomGuardJson = $RansomGuardReport | ConvertTo-Json -Depth 8
if ($OutputPath) { $RansomGuardJson | Set-Content -LiteralPath $OutputPath -Encoding UTF8 }
$RansomGuardJson
