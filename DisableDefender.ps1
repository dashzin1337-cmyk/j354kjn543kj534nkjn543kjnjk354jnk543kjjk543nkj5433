#DISABLE DEFENDER SCRIPT BY ZOIC

# ════════════════════════════════════════════════════════════════════════════
# LOGGING INFRASTRUCTURE
# ════════════════════════════════════════════════════════════════════════════
$script:LogFile    = "$env:TEMP\DisableDefender_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$script:StageTimer = $null
$script:StageNum   = 0
$script:Errors     = [System.Collections.Generic.List[string]]::new()
$script:Warnings   = [System.Collections.Generic.List[string]]::new()

# Core logger — writes timestamped, levelled lines to the txt file AND console
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','STEP','DATA','HEADER','SEP')]
        [string]$Level = 'INFO'
    )
    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $entry = switch ($Level) {
        'HEADER' { "`n$('=' * 90)`n  $Message`n$('=' * 90)" }
        'SEP'    { "$('-' * 90)" }
        default  { "[$ts] [$($Level.PadRight(7))] $Message" }
    }
    Add-Content -Path $script:LogFile -Value $entry -Encoding UTF8
    if ($Level -eq 'ERROR')   { $script:Errors.Add("[$ts] $Message") }
    if ($Level -eq 'WARN')    { $script:Warnings.Add("[$ts] $Message") }
    switch ($Level) {
        'ERROR'  { Write-Host $entry -ForegroundColor Red }
        'WARN'   { Write-Host $entry -ForegroundColor Yellow }
        'SUCCESS'{ Write-Host $entry -ForegroundColor Green }
        'STEP'   { Write-Host $entry -ForegroundColor Cyan }
        'HEADER' { Write-Host $entry -ForegroundColor Magenta }
        'DATA'   { Write-Host $entry -ForegroundColor Gray }
        default  { Write-Host $entry }
    }
}

# Writes a blank line as visual separator
function Write-LogBlank { Add-Content -Path $script:LogFile -Value '' -Encoding UTF8 }

# Begins a named stage — prints header and starts a stopwatch
function Start-Stage {
    param([string]$Name)
    $script:StageNum++
    $script:StageTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-LogBlank
    Write-Log "STAGE $($script:StageNum): $Name" 'HEADER'
}

# Ends the current stage — prints elapsed time
function End-Stage {
    param([string]$Name = '')
    $script:StageTimer.Stop()
    $elapsed = $script:StageTimer.Elapsed.ToString('mm\:ss\.fff')
    Write-Log "Stage completed in $elapsed" 'SUCCESS'
    Write-Log '' 'SEP'
}

# Runs a block, captures all output+errors, logs everything with timing
function Invoke-Logged {
    param([string]$Label, [scriptblock]$Block)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log "  --> $Label" 'STEP'
    try {
        $out = & $Block 2>&1
        $sw.Stop()
        if ($out) {
            foreach ($line in ($out | Out-String).Split("`n")) {
                $l = $line.TrimEnd()
                if ($l) { Write-Log "      $l" 'DATA' }
            }
        }
        Write-Log "  <-- $Label | exit=$LASTEXITCODE | elapsed=$($sw.Elapsed.ToString('ss\.fff'))s" 'SUCCESS'
    } catch {
        $sw.Stop()
        Write-Log "  <-- $Label | EXCEPTION after $($sw.Elapsed.ToString('ss\.fff'))s: $($_.Exception.Message)" 'ERROR'
        Write-Log "      ScriptStackTrace: $($_.ScriptStackTrace)" 'ERROR'
    }
}

# Dumps every property of an object as key=value lines
function Write-LogObject {
    param([string]$Label, $Obj)
    Write-Log "  [$Label]" 'STEP'
    if ($null -eq $Obj) { Write-Log "      (null)" 'WARN'; return }
    $Obj | Get-Member -MemberType Properties | ForEach-Object {
        $name = $_.Name
        try { $val = $Obj.$name } catch { $val = "(access error: $_)" }
        Write-Log "      $($name.PadRight(40)) = $val" 'DATA'
    }
}

# Snapshots all Defender-related services with full detail
function Write-ServiceSnapshot {
    param([string]$Label)
    Write-Log "  -- Service Snapshot: $Label --" 'STEP'
    $svcNames = @(
        'WinDefend','WdNisSvc','WdNisDrv','WdFilter','WdBoot',
        'wscsvc','SecurityHealthService','Sense','MpDefenderCoreService',
        'SgrmAgent','SgrmBroker','webthreatdefusersvc','webthreatdefsvc',
        'MsSecCore','MsSecFlt','MsSecWfp','MsMpEng'
    )
    foreach ($name in $svcNames) {
        try {
            $svc = Get-Service -Name $name -ErrorAction Stop
            $wmi = Get-WmiObject Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
            $pid_ = if ($wmi) { $wmi.ProcessId } else { 'N/A' }
            $path = if ($wmi) { $wmi.PathName } else { 'N/A' }
            $start= if ($wmi) { $wmi.StartMode } else { 'N/A' }
            $acct = if ($wmi) { $wmi.StartName } else { 'N/A' }
            Write-Log ("      {0,-35} Status={1,-10} StartType={2,-12} PID={3,-8} Account={4}" -f `
                $name, $svc.Status, $start, $pid_, $acct) 'DATA'
            Write-Log ("      {0,-35} BinPath={1}" -f '', $path) 'DATA'
        } catch {
            Write-Log "      $($name.PadRight(35)) NOT FOUND / NOT INSTALLED" 'WARN'
        }
    }
}

# Snapshots all Defender-related running processes with full detail
function Write-ProcessSnapshot {
    param([string]$Label)
    Write-Log "  -- Process Snapshot: $Label --" 'STEP'
    $procNames = @(
        'MsMpEng','MpCmdRun','OFFmeansOFF','NisSrv','MpDefenderCoreService',
        'smartscreen','SecurityHealthService','SecurityHealthSystray',
        'SgrmBroker','TrustedInstaller','wscsvc'
    )
    foreach ($name in $procNames) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($p in $procs) {
                Write-Log ("      {0,-35} PID={1,-7} CPU={2,-10} WS={3,-12} Path={4}" -f `
                    $name, $p.Id, "$([math]::Round($p.TotalProcessorTime.TotalSeconds,2))s", `
                    "$([math]::Round($p.WorkingSet64/1MB,1))MB", $p.Path) 'DATA'
            }
        } else {
            Write-Log "      $($name.PadRight(35)) (not running)" 'DATA'
        }
    }
}

# Reads a registry value and logs it; returns current value or $null
function Read-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop | Select-Object -ExpandProperty $Name
        Write-Log "      REG  $Path\$Name = $val" 'DATA'
        return $val
    } catch {
        Write-Log "      REG  $Path\$Name = (not found)" 'DATA'
        return $null
    }
}

# Dumps a full registry key (all values)
function Dump-RegKey {
    param([string]$Path)
    try {
        $props = Get-ItemProperty -Path $Path -ErrorAction Stop
        $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            Write-Log "      $($_.Name.PadRight(50)) = $($_.Value)" 'DATA'
        }
    } catch {
        Write-Log "      (key not readable or does not exist: $Path)" 'WARN'
    }
}

# Collects recent Windows Defender event log entries
function Write-DefenderEvents {
    param([int]$MaxEvents = 30)
    Write-Log "  -- Windows Defender Event Log (last $MaxEvents entries) --" 'STEP'
    try {
        $events = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' `
            -MaxEvents $MaxEvents -ErrorAction Stop
        foreach ($ev in $events) {
            Write-Log ("      [{0}] ID={1,-6} Level={2,-10} {3}" -f `
                $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $ev.Id, $ev.LevelDisplayName, `
                ($ev.Message -replace "`r`n",' ' -replace "`n",' ').Substring(0,[math]::Min(120,$ev.Message.Length))) 'DATA'
        }
    } catch {
        Write-Log "      Could not read Defender event log: $_" 'WARN'
    }
}

# Dumps Tamper Protection and key Defender registry state
function Write-DefenderRegistryState {
    param([string]$Label)
    Write-Log "  -- Defender Registry State: $Label --" 'STEP'
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows Defender',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
        'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection',
        'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features',
        'HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet',
        'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend'
    )
    foreach ($key in $keys) {
        Write-Log "    Key: $key" 'STEP'
        Dump-RegKey $key
    }
}

# Writes system environment info block
function Write-SystemInfo {
    Write-Log "  -- System Information --" 'STEP'
    $os  = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cpu = Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $cs  = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue
    $bi  = Get-WmiObject Win32_BIOS -ErrorAction SilentlyContinue
    $id  = [Security.Principal.WindowsIdentity]::GetCurrent()

    Write-Log "      ComputerName          = $env:COMPUTERNAME" 'DATA'
    Write-Log "      UserName              = $env:USERNAME" 'DATA'
    Write-Log "      WindowsIdentity       = $($id.Name)" 'DATA'
    Write-Log "      Identity Groups       = $($id.Groups.Translate([Security.Principal.NTAccount]) -join ', ')" 'DATA'
    Write-Log "      OS Caption            = $($os.Caption)" 'DATA'
    Write-Log "      OS Version            = $($os.Version)" 'DATA'
    Write-Log "      OS BuildNumber        = $($os.BuildNumber)" 'DATA'
    Write-Log "      OS Architecture       = $($os.OSArchitecture)" 'DATA'
    Write-Log "      OS InstallDate        = $($os.ConvertToDateTime($os.InstallDate))" 'DATA'
    Write-Log "      OS LastBootUpTime     = $($os.ConvertToDateTime($os.LastBootUpTime))" 'DATA'
    Write-Log "      OS FreePhysicalMem    = $([math]::Round($os.FreePhysicalMemory/1MB,2)) GB" 'DATA'
    Write-Log "      OS TotalVisibleMem    = $([math]::Round($os.TotalVisibleMemorySize/1MB,2)) GB" 'DATA'
    Write-Log "      CPU Name              = $($cpu.Name)" 'DATA'
    Write-Log "      CPU Cores             = $($cpu.NumberOfCores)" 'DATA'
    Write-Log "      CPU Logical           = $($cpu.NumberOfLogicalProcessors)" 'DATA'
    Write-Log "      Manufacturer          = $($cs.Manufacturer)" 'DATA'
    Write-Log "      Model                 = $($cs.Model)" 'DATA'
    Write-Log "      BIOS Version          = $($bi.SMBIOSBIOSVersion)" 'DATA'
    Write-Log "      BIOS ReleaseDate      = $($bi.ReleaseDate)" 'DATA'
    Write-Log "      PowerShell Version    = $($PSVersionTable.PSVersion)" 'DATA'
    Write-Log "      PowerShell Edition    = $($PSVersionTable.PSEdition)" 'DATA'
    Write-Log "      CLR Version           = $($PSVersionTable.CLRVersion)" 'DATA'
    Write-Log "      ExecutionPolicy       = $(Get-ExecutionPolicy)" 'DATA'
    Write-Log "      PSCommandPath         = $PSCommandPath" 'DATA'
    Write-Log "      TEMP directory        = $env:TEMP" 'DATA'
    Write-Log "      SystemDrive           = $env:SystemDrive" 'DATA'
    Write-Log "      ProgramFiles          = $env:ProgramFiles" 'DATA'
    Write-Log "      ProgramData           = $env:ProgramData" 'DATA'
    Write-Log "      Uptime                = $((Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime))" 'DATA'

    # Windows Defender product version
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mpStatus) {
        Write-Log "      AMProductVersion      = $($mpStatus.AMProductVersion)" 'DATA'
        Write-Log "      AMEngineVersion       = $($mpStatus.AMEngineVersion)" 'DATA'
        Write-Log "      AntispywareEnabled    = $($mpStatus.AntispywareEnabled)" 'DATA'
        Write-Log "      AntivirusEnabled      = $($mpStatus.AntivirusEnabled)" 'DATA'
        Write-Log "      RealTimeProtection    = $($mpStatus.RealTimeProtectionEnabled)" 'DATA'
        Write-Log "      TamperProtection      = $($mpStatus.IsTamperProtected)" 'DATA'
        Write-Log "      BehaviorMonitor       = $($mpStatus.BehaviorMonitorEnabled)" 'DATA'
        Write-Log "      IoavProtection        = $($mpStatus.IoavProtectionEnabled)" 'DATA'
        Write-Log "      NetworkInspection     = $($mpStatus.NISEnabled)" 'DATA'
        Write-Log "      OnAccessProtection    = $($mpStatus.OnAccessProtectionEnabled)" 'DATA'
        Write-Log "      AMRunningMode         = $($mpStatus.AMRunningMode)" 'DATA'
        Write-Log "      AMServiceEnabled      = $($mpStatus.AMServiceEnabled)" 'DATA'
        Write-Log "      AMServiceVersion      = $($mpStatus.AMServiceVersion)" 'DATA'
        Write-Log "      QuickScanAge(days)    = $($mpStatus.QuickScanAge)" 'DATA'
        Write-Log "      FullScanAge(days)     = $($mpStatus.FullScanAge)" 'DATA'
        Write-Log "      SignatureAge(days)    = $($mpStatus.AntivirusSignatureAge)" 'DATA'
        Write-Log "      SignatureLastUpdated  = $($mpStatus.AntivirusSignatureLastUpdated)" 'DATA'
        Write-Log "      SignatureVersion      = $($mpStatus.AntivirusSignatureVersion)" 'DATA'
    } else {
        Write-Log "      Get-MpComputerStatus  = UNAVAILABLE (Defender may already be disabled or cmdlet missing)" 'WARN'
    }
}

# Dump Defender scheduled tasks with full detail
function Write-DefenderTasks {
    param([string]$Label)
    Write-Log "  -- Scheduled Tasks: $Label --" 'STEP'
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like 'Windows Defender*' }
    Write-Log "      Total Defender tasks found: $($tasks.Count)" 'DATA'
    foreach ($t in $tasks) {
        Write-Log "      Task: '$($t.TaskName)'" 'DATA'
        Write-Log "            Path    : $($t.TaskPath)" 'DATA'
        Write-Log "            State   : $($t.State)" 'DATA'
        Write-Log "            URI     : $($t.URI)" 'DATA'
        try {
            $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
            Write-Log "            LastRun : $($info.LastRunTime)" 'DATA'
            Write-Log "            NextRun : $($info.NextRunTime)" 'DATA'
            Write-Log "            LastResult: $($info.LastTaskResult)" 'DATA'
        } catch {}
    }
}

# Write file existence + hash check for key Defender binaries
function Write-DefenderFiles {
    param([string]$Label)
    Write-Log "  -- Defender File Check: $Label --" 'STEP'
    $files = @(
        "$env:ProgramFiles\Windows Defender\MpCmdRun.exe",
        "$env:ProgramFiles\Windows Defender\OFFmeansOFF.exe",
        "$env:ProgramFiles\Windows Defender\MsMpEng.exe",
        "$env:ProgramFiles\Windows Defender\NisSrv.exe",
        "$env:ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db",
        "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Service",
        "$env:windir\System32\smartscreen.exe",
        "$env:windir\System32\SecurityHealthService.exe",
        "$env:windir\System32\SecurityHealthSystray.exe"
    )
    foreach ($f in $files) {
        if (Test-Path $f -PathType Leaf) {
            try {
                $hash = (Get-FileHash $f -Algorithm SHA256 -ErrorAction Stop).Hash
                $fi   = Get-Item $f
                Write-Log ("      EXISTS   {0,-65} {1,10} KB  SHA256={2}" -f $f, [math]::Round($fi.Length/1KB,1), $hash) 'DATA'
            } catch {
                Write-Log "      EXISTS   $f  (hash failed: $_)" 'WARN'
            }
        } elseif (Test-Path $f -PathType Container) {
            $count = (Get-ChildItem $f -Recurse -File -ErrorAction SilentlyContinue).Count
            Write-Log "      DIR      $f  ($count files inside)" 'DATA'
        } else {
            Write-Log "      MISSING  $f" 'DATA'
        }
    }
}

# ════════════════════════════════════════════════════════════════════════════
# SCRIPT BANNER + INITIAL STATE CAPTURE
# ════════════════════════════════════════════════════════════════════════════
$ScriptStartTime = Get-Date

Write-Log "DisableDefender Script — Execution Report" 'HEADER'
Write-Log "Report file : $script:LogFile" 'INFO'
Write-Log "Start time  : $($ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss.fff'))" 'INFO'
Write-Log '' 'SEP'

Write-SystemInfo

Write-Log '' 'SEP'
Write-Log "PRE-RUN STATE" 'HEADER'
Write-ServiceSnapshot "PRE-RUN"
Write-LogBlank
Write-ProcessSnapshot "PRE-RUN"
Write-LogBlank
Write-DefenderRegistryState "PRE-RUN"
Write-LogBlank
Write-DefenderFiles "PRE-RUN"
Write-LogBlank
Write-DefenderTasks "PRE-RUN"
Write-LogBlank
Write-DefenderEvents 50

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
  Write-Log "Not running as Administrator — relaunching elevated..." 'WARN'
  Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
  Exit
}

Write-Log "Administrator privilege check: PASSED" 'SUCCESS'

#reg files
$file1 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender]
"DisableRoutinelyTakingAction"=dword:00000001
"ServiceKeepAlive"=dword:00000000
"AllowFastServiceStartup"=dword:00000000
"DisableLocalAdminMerge"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection]
"LocalSettingOverrideDisableOnAccessProtection"=dword:00000000
"LocalSettingOverrideRealtimeScanDirection"=dword:00000000
"LocalSettingOverrideDisableIOAVProtection"=dword:00000000
"LocalSettingOverrideDisableBehaviorMonitoring"=dword:00000000
"LocalSettingOverrideDisableIntrusionPreventionSystem"=dword:00000000
"LocalSettingOverrideDisableRealtimeMonitoring"=dword:00000000
"DisableIOAVProtection"=dword:00000001
"DisableRealtimeMonitoring"=dword:00000001
"DisableBehaviorMonitoring"=dword:00000001
"DisableOnAccessProtection"=dword:00000001
"DisableScanOnRealtimeEnable"=dword:00000001
"RealtimeScanDirection"=dword:00000002
"DisableInformationProtectionControl"=dword:00000001
"DisableIntrusionPreventionSystem"=dword:00000001
"DisableRawWriteNotification"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender]
"DisableRoutinelyTakingAction"=dword:00000001
'@
$file2 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIOAVProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender]
"PUAProtection"=dword:00000000
"DisableRoutinelyTakingAction"=dword:00000001
"ServiceKeepAlive"=dword:00000000
"AllowFastServiceStartup"=dword:00000000
"DisableLocalAdminMerge"=dword:00000001
"DisableAntiSpyware"=dword:00000001
"RandomizeScheduleTaskTimes"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowArchiveScanning]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowCloudProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowEmailScanning]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowFullScanOnMappedNetworkDrives]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowFullScanRemovableDriveScanning]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIntrusionPreventionSystem]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowOnAccessProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowRealtimeMonitoring]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScanningNetworkFiles]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScriptScanning]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowUserUIAccess]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\CheckForSignaturesBeforeRunningScan]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\CloudBlockLevel]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\CloudExtendedTimeout]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\DaysToRetainCleanedMalware]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupFullScan]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupQuickScan]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableControlledFolderAccess]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableLowCPUPriority]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableNetworkProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\PUAProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\RealTimeScanDirection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScanParameter]
"value"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScheduleScanDay]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScheduleScanTime]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\SignatureUpdateInterval]
"value"=dword:00000018

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\SubmitSamplesConsent]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions]
"DisableAutoExclusions"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine]
"MpEnablePus"=dword:00000000
"MpCloudBlockLevel"=dword:00000000
"MpBafsExtendedTimeout"=dword:00000000
"EnableFileHashComputation"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS]
"ThrottleDetectionEventsRate"=dword:00000000
"DisableSignatureRetirement"=dword:00000001
"DisableProtocolRecognition"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager]
"DisableScanningNetworkFiles"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection]
"DisableRealtimeMonitoring"=dword:00000001
"DisableBehaviorMonitoring"=dword:00000001
"DisableOnAccessProtection"=dword:00000001
"DisableScanOnRealtimeEnable"=dword:00000001
"DisableIOAVProtection"=dword:00000001
"LocalSettingOverrideDisableOnAccessProtection"=dword:00000000
"LocalSettingOverrideRealtimeScanDirection"=dword:00000000
"LocalSettingOverrideDisableIOAVProtection"=dword:00000000
"LocalSettingOverrideDisableBehaviorMonitoring"=dword:00000000
"LocalSettingOverrideDisableIntrusionPreventionSystem"=dword:00000000
"LocalSettingOverrideDisableRealtimeMonitoring"=dword:00000000
"RealtimeScanDirection"=dword:00000002
"IOAVMaxSize"=dword:00000512
"DisableInformationProtectionControl"=dword:00000001
"DisableIntrusionPreventionSystem"=dword:00000001
"DisableRawWriteNotification"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan]
"LowCpuPriority"=dword:00000001
"DisableRestorePoint"=dword:00000001
"DisableArchiveScanning"=dword:00000000
"DisableScanningNetworkFiles"=dword:00000000
"DisableCatchupFullScan"=dword:00000000
"DisableCatchupQuickScan"=dword:00000001
"DisableEmailScanning"=dword:00000000
"DisableHeuristics"=dword:00000001
"DisableReparsePointScanning"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates]
"SignatureDisableNotification"=dword:00000001
"RealtimeSignatureDelivery"=dword:00000000
"ForceUpdateFromMU"=dword:00000000
"DisableScheduledSignatureUpdateOnBattery"=dword:00000001
"UpdateOnStartUp"=dword:00000000
"SignatureUpdateCatchupInterval"=dword:00000002
"DisableUpdateOnStartupWithoutEngine"=dword:00000001
"ScheduleTime"=dword:00001440
"DisableScanOnUpdate"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet]
"DisableBlockAtFirstSeen"=dword:00000001
"LocalSettingOverrideSpynetReporting"=dword:00000000
"SpynetReporting"=dword:00000000
"SubmitSamplesConsent"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration]
"SuppressRebootNotification"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access]
"EnableControlledFolderAccess"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection]
"EnableNetworkProtection"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender]
"DisableRoutinelyTakingAction"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware]
"ServiceKeepAlive"=dword:00000000
"AllowFastServiceStartup"=dword:00000000
"DisableRoutinelyTakingAction"=dword:00000001
"DisableAntiSpyware"=dword:00000001
"DisableAntiVirus"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\SpyNet]
"SpyNetReporting"=dword:00000000
"LocalSettingOverrideSpyNetReporting"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting]
"DisableEnhancedNotifications"=dword:00000001
"DisableGenericRePorts"=dword:00000001
"WppTracingLevel"=dword:00000000
"WppTracingComponents"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Policy]
"VerifiedAndReputablePolicyState"=dword:00000000
'@
$file3 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableEnhancedNotifications]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableNotifications]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\HideWindowsSecurityNotificationAreaControl]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center]
"FirstRunDisabled"=dword:00000001
"AntiVirusOverride"=dword:00000001
"FirewallOverride"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications]
"DisableEnhancedNotifications"=dword:00000001
"DisableNotifications"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance]
"Enabled"=dword:00000000
'@
$file5 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\Software\Classes\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}]

[-HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]

[-HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]

[-HKEY_CLASSES_ROOT\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}]

[-HKEY_CLASSES_ROOT\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}]

[-HKEY_CLASSES_ROOT\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}]

[-HKEY_CLASSES_ROOT\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}]

[-HKEY_CLASSES_ROOT\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}]

[-HKEY_CLASSES_ROOT\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}]

[-HKEY_CLASSES_ROOT\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}]

[-HKEY_CLASSES_ROOT\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}]

[-HKEY_CLASSES_ROOT\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}]

[-HKEY_CLASSES_ROOT\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}]

[-HKEY_CLASSES_ROOT\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}]

[-HKEY_CLASSES_ROOT\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger]
'@
$file6 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0ACC9108-2000-46C0-8407-5FD9F89521E8}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{1D77BCC8-1D07-42D0-8C89-3A98674DFB6F}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4A9233DB-A7D3-45D6-B476-8C7D8DF73EB5}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B05F34EE-83F2-413D-BC1D-7D5BD6E98300}]
'@
$file7 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecCore]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefsvc]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmAgent]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend]

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection]
"DisallowExploitProtectionOverride"=dword:00000001

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecWfp]
'@
$file8 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend]

[-HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\windowsdefender]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppUserModelId\Windows.Defender]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppUserModelId\Microsoft.Windows.Defender]

[-HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0]

[-HKEY_CURRENT_USER\Software\Classes\ms-cxh]

[-HKEY_CLASSES_ROOT\Local Settings\MrtCache\C:%5CWindows%5CSystemApps%5CMicrosoft.Windows.AppRep.ChxApp_cw5n1h2txyewy%5Cresources.pri]

[-HKEY_CLASSES_ROOT\WindowsDefender]

[-HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WindowsDefender]

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Ubpm]
"CriticalMaintenance_DefenderCleanup"=-
"CriticalMaintenance_DefenderVerification"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Ubpm]
"CriticalMaintenance_DefenderCleanup"=-
"CriticalMaintenance_DefenderVerification"=-

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System]
"WindowsDefender-1"=-
"WindowsDefender-2"=-
"WindowsDefender-3"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System]
"WindowsDefender-1"=-
"WindowsDefender-2"=-
"WindowsDefender-3"=-
'@
$file9 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates]
"SignatureDisableNotification"=dword:00000001
"RealtimeSignatureDelivery"=dword:00000000
"ForceUpdateFromMU"=dword:00000000
"DisableScheduledSignatureUpdateOnBattery"=dword:00000001
"UpdateOnStartUp"=dword:00000000
"SignatureUpdateCatchupInterval"=dword:00000002
"DisableUpdateOnStartupWithoutEngine"=dword:00000001
"ScheduleTime"=dword:00001440
"DisableScanOnUpdate"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"EnableSmartScreen"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen]
"ConfigureAppInstallControlEnabled"=dword:00000001
"ConfigureAppInstallControl"="Anywhere"

[HKEY_CURRENT_USER\Software\Microsoft\Windows Security Health\State]
"AppAndBrowser_EdgeSmartScreenOff"=dword:00000001
"AppAndBrowser_StoreAppsSmartScreenOff"=dword:00000001
"AppAndBrowser_PuaSmartScreenOff"=dword:00000001
'@
$file10 = @'
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"Windows Defender"=-
"SecurityHealth"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run]
"Windows Defender"=-
"SecurityHealth"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"WindowsDefender"=-
"SecurityHealth"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\open]
"NoSmartScreen"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\runas]
"NoSmartScreen"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\runasuser]
"NoSmartScreen"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SmartScreen.exe]
"Debugger"="systray.exe"

'@
$file11 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}]

[-HKEY_CLASSES_ROOT\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]

[-HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.Service.UserSessionServiceManager]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.ThreatExperienceManager.ThreatExperienceManager]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.ThreatResponseEngine.ThreatDecisionEngine]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.Configuration.WTDUserSettings]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}]

[-HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}]
'@

#exploit trusted installer service bin path
function Run-Trusted([String]$command) {
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  Write-Log "  Run-Trusted ENTER" 'STEP'
  Write-Log "      Command (plain)      : $command" 'DATA'

  # Pre-state: TrustedInstaller
  $tiSvc = Get-WmiObject Win32_Service -Filter "Name='TrustedInstaller'" -ErrorAction SilentlyContinue
  if ($null -eq $tiSvc) {
    Write-Log "      TrustedInstaller WMI object NOT FOUND — cannot proceed!" 'ERROR'
    return
  }
  $DefaultBinPath = $tiSvc.PathName
  Write-Log "      TI state (pre)       : Status=$($tiSvc.State) StartMode=$($tiSvc.StartMode) PID=$($tiSvc.ProcessId)" 'DATA'
  Write-Log "      TI binPath (original): $DefaultBinPath" 'DATA'

  # Stop TI before hijacking
  $stopOut = Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue 2>&1
  Write-Log "      sc stop (pre)        : $stopOut" 'DATA'

  # Encode command to base64
  $bytes         = [System.Text.Encoding]::Unicode.GetBytes($command)
  $base64Command = [Convert]::ToBase64String($bytes)
  Write-Log "      Base64 length        : $($base64Command.Length) chars" 'DATA'

  # Hijack binPath
  $newBin  = "cmd.exe /c powershell.exe -encodedcommand $base64Command"
  $cfgOut  = sc.exe config TrustedInstaller binPath= $newBin 2>&1
  Write-Log "      sc config result     : $cfgOut" 'DATA'

  # Verify change
  $tiPost = Get-WmiObject Win32_Service -Filter "Name='TrustedInstaller'" -ErrorAction SilentlyContinue
  Write-Log "      TI binPath (new)     : $($tiPost.PathName)" 'DATA'

  # Start to execute command
  $startOut = sc.exe start TrustedInstaller 2>&1
  Write-Log "      sc start result      : $startOut" 'DATA'

  # Wait longer — SCM reports 1053 (timeout) but the payload (cmd->powershell) still runs.
  # We need to let the payload finish before restoring binPath, otherwise it gets killed mid-run.
  # Poll for TrustedInstaller to appear as a process, then wait for it to exit (max 30s).
  $waited = 0
  $maxWait = 30
  while ($waited -lt $maxWait) {
    Start-Sleep -Milliseconds 500
    $tiProc = Get-Process -Name 'TrustedInstaller' -ErrorAction SilentlyContinue
    if ($tiProc) {
      Write-Log "      TI process appeared   : PID=$($tiProc.Id) (waiting for completion...)" 'DATA'
      # Now wait for it to finish (payload runs inside cmd.exe child, TI exits when cmd exits)
      $tiProc.WaitForExit(20000) | Out-Null
      Write-Log "      TI process exited." 'DATA'
      break
    }
    $waited++
  }
  if ($waited -ge $maxWait) {
    Write-Log "      TI process never appeared — payload may have run via SCM timeout path." 'WARN'
    # Still give it time — the cmd.exe child keeps running even after TI exits with 1053
    Start-Sleep -Seconds 3
  }

  # Restore original binPath
  $restoreOut = sc.exe config TrustedInstaller binpath= "`"$DefaultBinPath`"" 2>&1
  Write-Log "      sc restore result    : $restoreOut" 'DATA'

  # Verify restore
  $tiRestored = Get-WmiObject Win32_Service -Filter "Name='TrustedInstaller'" -ErrorAction SilentlyContinue
  $restoredMatch = ($tiRestored.PathName -like "*trustedinstaller*")
  Write-Log "      TI binPath (restored): $($tiRestored.PathName)  [match=$restoredMatch]" 'DATA'
  if (-not $restoredMatch) {
    Write-Log "      WARNING: binPath restore may have failed!" 'WARN'
  }

  # Final stop
  Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue | Out-Null
  $tiFinal = Get-WmiObject Win32_Service -Filter "Name='TrustedInstaller'" -ErrorAction SilentlyContinue
  Write-Log "      TI state (post)      : Status=$($tiSvc.State)" 'DATA'

  $sw.Stop()
  Write-Log "  Run-Trusted EXIT  elapsed=$($sw.Elapsed.ToString('ss\.fff'))s" 'SUCCESS'
}


#refactor of https://github.com/AveYo/LeanAndMean/blob/main/disableDefender.ps1
$code = @'
$InnerLog = "$env:TEMP\DefeatDefend_inner_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function IL { param([string]$M,[string]$L='INFO'); $e="[$(Get-Date -Format 'HH:mm:ss')] [$L] $M"; Add-Content $InnerLog $e -Encoding UTF8; Write-Host $e }
IL "defeatMsMpEng inner script started" 'STEP'
IL "Running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)" 'INFO'

function defeatMsMpEng {
    
$key = 'Registry::HKU\S-1-5-21-*\Volatile Environment'
    
# Define types and modules
$I = [int32]
$M = $I.module.GetType("System.Runtime.InteropServices.Marshal")
$P = $I.module.GetType("System.IntPtr")
$S = [string]
$D = @()
$DM = [AppDomain]::CurrentDomain.DefineDynamicAssembly(1, 1).DefineDynamicModule(1)
$U = [uintptr]
$Z = [uintptr]::Size

# Define dynamic types
0..5 | ForEach-Object { $D += $DM.DefineType("AveYo_$_", 1179913, [ValueType]) }
$D += $U
4..6 | ForEach-Object { $D += $D[$_].MakeByRefType() }

# Define PInvoke methods
$F = @(
    'kernel', 'CreateProcess', ($S, $S, $I, $I, $I, $I, $I, $S, $D[7], $D[8]),
    'advapi', 'RegOpenKeyEx', ($U, $S, $I, $I, $D[9]),
    'advapi', 'RegSetValueEx', ($U, $S, $I, $I, [byte[]], $I),
    'advapi', 'RegFlushKey', ($U),
    'advapi', 'RegCloseKey', ($U)
)
0..4 | ForEach-Object { $9 = $D[0].DefinePInvokeMethod($F[3 * $_ + 1], $F[3 * $_] + "32", 8214, 1, $S, $F[3 * $_ + 2], 1, 4) }

# Define fields
$DF = @(
    ($P, $I, $P),
    ($I, $I, $I, $I, $P, $D[1]),
    ($I, $S, $S, $S, $I, $I, $I, $I, $I, $I, $I, $I, [int16], [int16], $P, $P, $P, $P),
    ($D[3], $P),
    ($P, $P, $I, $I)
)
1..5 | ForEach-Object { $k = $_; $n = 1; $DF[$_ - 1] | ForEach-Object { $9 = $D[$k].DefineField("f" + $n++, $_, 6) } }

# Create types
$T = @()
0..5 | ForEach-Object { $T += $D[$_].CreateType() }

# Create instances
0..5 | ForEach-Object { New-Variable -Name "A$_" -Value ([Activator]::CreateInstance($T[$_])) -Force }

# Define functions
function F ($1, $2) { $T[0].GetMethod($1).Invoke(0, $2) }
function M ($1, $2, $3) { $M.GetMethod($1, [type[]]$2).Invoke(0, $3) }

# Allocate memory
$H = @()
$Z, (4 * $Z + 16) | ForEach-Object { $H += M "AllocHGlobal" $I $_ }

# Check user and start service if necessary
if ([environment]::username -ne "system") {
    IL "Not running as SYSTEM (user: $([environment]::username)) — launching via TrustedInstaller impersonation..." 'WARN'
    $TI = "TrustedInstaller"
    Start-Service $TI -ErrorAction SilentlyContinue
    $As = Get-Process -Name $TI -ErrorAction SilentlyContinue
    if ($null -eq $As) { IL "WARNING: TrustedInstaller process not found after Start-Service!" 'ERROR' }
    else { IL "TrustedInstaller process found. PID: $($As.Id)" 'INFO' }
    M "WriteIntPtr" ($P, $P) ($H[0], $As.Handle)
    $A1.f1 = 131072
    $A1.f2 = $Z
    $A1.f3 = $H[0]
    $A2.f1 = 1
    $A2.f2 = 1
    $A2.f3 = 1
    $A2.f4 = 1
    $A2.f6 = $A1
    $A3.f1 = 10 * $Z + 32
    $A4.f1 = $A3
    $A4.f2 = $H[1]
    M "StructureToPtr" ($D[2], $P, [boolean]) (($A2 -as $D[2]), $A4.f2, $false)
    $R = @($null, "powershell -nop -c iex(`$env:R); # $id", 0, 0, 0, 0x0E080610, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
    IL "CreateProcess call dispatched for SYSTEM elevation." 'INFO'
    F 'CreateProcess' $R
    return
}

# Clear environment variable
IL "Running as SYSTEM — proceeding with defeatMsMpEng." 'SUCCESS'
$env:R = ''
Remove-ItemProperty -Path $key -Name $id -Force -ErrorAction SilentlyContinue

# Set privileges
$e = [diagnostics.process].GetMember('SetPrivilege', 42)[0]
'SeSecurityPrivilege', 'SeTakeOwnershipPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege' | ForEach-Object { $e.Invoke($null, @("$_", 2)) }

# Define function to set registry DWORD values
function RegSetDwords ($hive, $key, [array]$values, [array]$dword, $REG_TYPE = 4, $REG_ACCESS = 2, $REG_OPTION = 0) {
    $rok = ($hive, $key, $REG_OPTION, $REG_ACCESS, ($hive -as $D[9]))
    F "RegOpenKeyEx" $rok
    $rsv = $rok[4]
    $values | ForEach-Object { $i = 0 } { F "RegSetValueEx" ($rsv[0], [string]$_, 0, $REG_TYPE, [byte[]]($dword[$i]), 4); $i++ }
    F "RegFlushKey" @($rsv)
    F "RegCloseKey" @($rsv)
    $rok = $null
    $rsv = $null
}


 
    $disable = 1
    $disable_rev = 0
    $disable_SMARTSCREENFILTER = 1
    IL "Stopping wscsvc and killing MpCmdRun/OFFmeansOFF..." 'STEP'
    #stop security center and defender commandline exe
    stop-service 'wscsvc' -force -ErrorAction SilentlyContinue *>$null
    Stop-Process -name 'OFFmeansOFF', 'MpCmdRun' -force -ErrorAction SilentlyContinue
    IL "Services/processes stopped." 'INFO'
 
    $HKLM = [uintptr][uint32]2147483650 
    $VALUES = 'ServiceKeepAlive', 'PreviousRunningMode', 'IsServiceRunning', 'DisableAntiSpyware', 'DisableAntiVirus', 'PassiveMode'
    $DWORDS = 0, 0, 0, $disable, $disable, $disable
    IL "Applying registry values to Policies and Windows Defender keys..." 'STEP'
    #apply registry values (not all will apply)
    RegSetDwords $HKLM 'SOFTWARE\Policies\Microsoft\Windows Defender' $VALUES $DWORDS 
    RegSetDwords $HKLM 'SOFTWARE\Microsoft\Windows Defender' $VALUES $DWORDS
    IL "Registry values applied." 'INFO'
    [GC]::Collect() 
    Start-Sleep 1

    IL "Locating MpCmdRun.exe / OFFmeansOFF.exe in Windows Defender folder..." 'STEP'
    #run defender command line to disable msmpeng service
    Push-Location "$env:programfiles\Windows Defender"
    $mpcmdrun = ('OFFmeansOFF.exe', 'MpCmdRun.exe')[(test-path 'MpCmdRun.exe')]
    IL "Using executable: $mpcmdrun" 'INFO'
    Start-Process -wait $mpcmdrun -args '-DisableService -HighPriority'
    IL "DisableService command completed." 'INFO'

    #wait for service to close before continuing
    $wait = 14
    while ((get-process -name 'MsMpEng' -ea 0) -and $wait -gt 0) { 
        IL "Waiting for MsMpEng to stop... ($wait seconds left)" 'INFO'
        $wait--
        Start-Sleep 1
    }
    if (get-process -name 'MsMpEng' -ea 0) {
        IL "WARNING: MsMpEng is STILL running after wait timeout!" 'WARN'
    } else {
        IL "MsMpEng is no longer running." 'SUCCESS'
    }
 
    IL "Renaming MpCmdRun.exe to OFFmeansOFF.exe..." 'STEP'
    #rename defender commandline exe
    $location = split-path $(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' ImagePath -ErrorAction SilentlyContinue).ImagePath.Trim('"')
    IL "WinDefend image path location: $location" 'INFO'
    Push-Location $location
    try {
        Rename-Item MpCmdRun.exe -NewName 'OFFmeansOFF.exe' -force -ErrorAction Stop
        IL "Renamed MpCmdRun.exe -> OFFmeansOFF.exe" 'SUCCESS'
    } catch {
        IL "Failed to rename MpCmdRun.exe: $_" 'WARN'
    }
 
    IL "Cleaning up Defender scan history..." 'STEP'
    #cleanup scan history
    Remove-Item "$env:ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db" -force -ErrorAction SilentlyContinue
    Remove-Item "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Service" -recurse -force -ErrorAction SilentlyContinue
    IL "Scan history cleanup done." 'INFO'

    IL "Re-applying registry values (now MsMpEng is stopped)..." 'STEP'
    #apply keys that are blocked when msmpeng is running
    RegSetDwords $HKLM 'SOFTWARE\Policies\Microsoft\Windows Defender' $VALUES $DWORDS 
    RegSetDwords $HKLM 'SOFTWARE\Microsoft\Windows Defender' $VALUES $DWORDS
    IL "Post-kill registry values applied." 'SUCCESS'

    #disable smartscreen
    if ($disable_SMARTSCREENFILTER) {
        IL "Disabling SmartScreen..." 'STEP'
        try {
            Set-ItemProperty 'HKLM:\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState' 0 -type Dword -force -ErrorAction Stop
            IL "VerifiedAndReputablePolicyState set to 0" 'SUCCESS'
        } catch { IL "Failed VerifiedAndReputablePolicyState: $_" 'WARN' }
        try {
            Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' 'Off' -force -ErrorAction Stop
            IL "SmartScreenEnabled set to Off" 'SUCCESS'
        } catch { IL "Failed SmartScreenEnabled: $_" 'WARN' }
        Get-Item Registry::HKEY_Users\S-1-5-21*\Software\Microsoft -ea 0 | ForEach-Object {
            $userPath = $_.PSPath
            IL "Processing user hive: $userPath" 'INFO'
            try {
                Set-ItemProperty "$userPath\Windows\CurrentVersion\AppHost" 'EnableWebContentEvaluation' $disable_rev -type Dword -force -ErrorAction SilentlyContinue
                Set-ItemProperty "$userPath\Windows\CurrentVersion\AppHost" 'PreventOverride' $disable_rev -type Dword -force -ErrorAction SilentlyContinue
                New-Item "$userPath\Edge\SmartScreenEnabled" -ErrorAction SilentlyContinue *>$null
                Set-ItemProperty "$userPath\Edge\SmartScreenEnabled" '(Default)' $disable_rev -ErrorAction SilentlyContinue
                IL "  AppHost/Edge SmartScreen disabled for $userPath" 'SUCCESS'
            } catch {
                IL "  Failed user SmartScreen settings for $userPath : $_" 'WARN'
            }
        }
        if ($disable_rev -eq 0) { 
            IL "Killing smartscreen process..." 'INFO'
            Stop-Process -name smartscreen -force -ErrorAction SilentlyContinue
        }
        IL "SmartScreen disable complete." 'SUCCESS'
    }

}
defeatMsMpEng
IL "defeatMsMpEng inner script finished. Log: $InnerLog" 'STEP'
'@
$script = New-Item "$env:TEMP\DefeatDefend.ps1" -Value $code -Force
Write-Log "Temp defeatMsMpEng script written to: $($script.FullName)" 'INFO'
$run = "Start-Process powershell.exe -ArgumentList `"-executionpolicy bypass -File $($script.FullName) -Verb runas`""
Write-Log "Run command prepared: $run" 'INFO'


Write-Host 'Running Initial Stage...'
Start-Stage "Notification suppression and initial registry tweaks"

# Quick service snapshot at stage start (full PRE-RUN was already captured above)
Write-ServiceSnapshot "START OF STAGE 1"

#disable notifications and others that are allowed while defender is running
Invoke-Logged "Reg: DisableEnhancedNotifications" { Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' /v 'DisableEnhancedNotifications' /t REG_DWORD /d '1' /f 2>&1 }
Invoke-Logged "Reg: DisableNotifications" { Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' /v 'DisableNotifications' /t REG_DWORD /d '1' /f 2>&1 }
Invoke-Logged "Reg: SummaryNotificationDisabled" { Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'SummaryNotificationDisabled' /t REG_DWORD /d '1' /f 2>&1 }
Invoke-Logged "Reg: NoActionNotificationDisabled" { Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'NoActionNotificationDisabled' /t REG_DWORD /d '1' /f 2>&1 }
Invoke-Logged "Reg: FilesBlockedNotificationDisabled" { Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'FilesBlockedNotificationDisabled' /t REG_DWORD /d '1' /f 2>&1 }
Invoke-Logged "Reg: SecurityAndMaintenance toast disable" { Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance' /v 'Enabled' /t REG_DWORD /d '0' /f 2>&1 }

#exploit protection
Invoke-Logged "Reg: MitigationOptions (exploit protection)" { Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel' /v 'MitigationOptions' /t REG_BINARY /d '222222000001000000000000000000000000000000000000' /f 2>&1 }

Write-Log "  NOTE: sc.exe error 1053 is expected behavior — the cmd->powershell payload runs after SCM timeout. binPath is restored safely regardless." 'INFO'
Write-Log "  Run-Trusted: PUAProtection = 0" 'STEP'
Run-Trusted -command "Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender' /v 'PUAProtection' /t REG_DWORD /d '0' /f"
Write-Log "  Run-Trusted: SmartScreenEnabled = Off" 'STEP'
Run-Trusted -command "Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v 'SmartScreenEnabled' /t REG_SZ /d 'Off' /f"
Write-Log "  Run-Trusted: AicEnabled = Anywhere" 'STEP'
Run-Trusted -command "Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v 'AicEnabled' /t REG_SZ /d 'Anywhere' /f"

End-Stage "Notification suppression"

Write-Host 'Disabling Defender with Registry Hacks...'
Start-Stage "Writing and importing .reg files via TrustedInstaller"

Invoke-Logged "Create temp directory $env:TEMP\disableReg" {
    New-Item -Path "$env:TEMP\disableReg" -ItemType Directory -Force
}

$regFiles = @{
  'disable1.reg'  = $file1
  'disable2.reg'  = $file2
  'disable3.reg'  = $file3
  'disable5.reg'  = $file5
  'disable6.reg'  = $file6
  'disable7.reg'  = $file7
  'disable8.reg'  = $file8
  'disable9.reg'  = $file9
  'disable10.reg' = $file10
  'disable11.reg' = $file11
}

foreach ($name in $regFiles.Keys | Sort-Object) {
  $path = "$env:TEMP\disableReg\$name"
  try {
    New-Item -Path $path -Value $regFiles[$name] -Force | Out-Null
    $size = (Get-Item $path).Length
    Write-Log "  Written $name  ($size bytes) -> $path" 'SUCCESS'
  } catch {
    Write-Log "  FAILED to write $name : $_" 'ERROR'
  }
}

$files = (Get-ChildItem -Path "$env:TEMP\disableReg").FullName
Write-Log "  Total .reg files to import: $($files.Count)" 'INFO'

foreach ($file in $files) {
  $fname = Split-Path $file -Leaf
  Write-Log "  Importing $fname via TrustedInstaller regedit /s ..." 'STEP'
  $command = "Start-Process regedit.exe -ArgumentList `"/s $file`" -Wait"
  Run-Trusted -command $command
  Start-Sleep 1
  Write-Log "  Import done: $fname" 'SUCCESS'
}

End-Stage "Reg file imports"


#attempt to kill defender processes and silence notifications from sec center
Start-Stage "Kill Defender processes and services"
Write-Log "  Sending kill/stop command via TrustedInstaller..." 'INFO'
$command = 'Stop-Process -Name MpDefenderCoreService -Force -ErrorAction SilentlyContinue; Stop-Process -Name smartscreen -Force -ErrorAction SilentlyContinue; Stop-Process -Name SecurityHealthService -Force -ErrorAction SilentlyContinue; Stop-Process -Name SecurityHealthSystray -Force -ErrorAction SilentlyContinue; Stop-Service -Name wscsvc -Force -ErrorAction SilentlyContinue; Stop-Service -Name Sense -Force -ErrorAction SilentlyContinue'
Run-Trusted -command $command

Write-LogBlank
Write-ProcessSnapshot "AFTER process kills"
End-Stage "Process/service kills"

Start-Stage "defeatMsMpEng — main Defender defeat (runs as SYSTEM via TrustedInstaller)"
Write-Log "  Inner script path: $($script.FullName)" 'INFO'
$innerScriptExists = Test-Path $script.FullName
Write-Log "  Inner script exists on disk: $innerScriptExists" 'DATA'
if ($innerScriptExists) {
    $hash = (Get-FileHash $script.FullName -Algorithm SHA256).Hash
    $size = (Get-Item $script.FullName).Length
    Write-Log "  Inner script size  : $size bytes" 'DATA'
    Write-Log "  Inner script SHA256: $hash" 'DATA'
}
Run-Trusted -command $run
Write-Log "  defeatMsMpEng stage dispatched." 'INFO'
Write-Log "  NOTE: error 1053 from sc.exe is expected — the cmd->powershell payload runs async after SCM timeout." 'INFO'

# The inner script needs to: get a SYSTEM token via CreateProcess, re-launch itself as true SYSTEM,
# then call MpCmdRun -DisableService. This multi-hop can take 30-90 seconds.
# We poll MsMpEng until it stops (or timeout).
Write-Log "  Waiting for MsMpEng (PID=$((Get-Process MsMpEng -ea 0).Id)) to stop (max 120s)..." 'INFO'
$waited = 0
$msmpengStopped = $false
while ($waited -lt 120) {
    Start-Sleep -Seconds 2
    $waited += 2
    $mp = Get-Process -Name 'MsMpEng' -ErrorAction SilentlyContinue
    if (-not $mp) {
        Write-Log "  MsMpEng stopped after ${waited}s!" 'SUCCESS'
        $msmpengStopped = $true
        break
    }
    if ($waited % 10 -eq 0) {
        Write-Log "  MsMpEng still running at ${waited}s... PID=$($mp.Id) CPU=$([math]::Round($mp.TotalProcessorTime.TotalSeconds,1))s WS=$([math]::Round($mp.WorkingSet64/1MB,1))MB" 'INFO'
    }
}
if (-not $msmpengStopped) {
    Write-Log "  WARNING: MsMpEng did NOT stop within 120s. defeatMsMpEng likely failed to get SYSTEM token." 'WARN'
    Write-Log "  Check '$env:TEMP\DefeatDefend_inner_*.log' for details." 'WARN'
}

# Also check for the inner log file
Start-Sleep -Seconds 3
$innerLogs = Get-ChildItem "$env:TEMP\DefeatDefend_inner_*.log" -ErrorAction SilentlyContinue
if ($innerLogs) {
    foreach ($il in $innerLogs) {
        Write-Log "  Inner log found: $($il.FullName) ($($il.Length) bytes)" 'SUCCESS'
        Write-Log "  -- Inner Log Contents --" 'STEP'
        Get-Content $il.FullName | ForEach-Object { Write-Log "    $_" 'DATA' }
    }
} else {
    Write-Log "  No inner DefeatDefend_inner_*.log found yet." 'WARN'
}
End-Stage "defeatMsMpEng dispatch"

Start-Stage "Disable Windows Defender scheduled tasks"
$allTasks      = Get-ScheduledTask -ErrorAction SilentlyContinue
$defenderTasks = $allTasks | Where-Object { $_.TaskName -like 'Windows Defender*' }
Write-Log "  Total scheduled tasks on system   : $($allTasks.Count)" 'DATA'
Write-Log "  Defender-related tasks found       : $($defenderTasks.Count)" 'DATA'
foreach ($task in $defenderTasks) {
  Write-Log "  Task: '$($task.TaskName)'  Path=$($task.TaskPath)  State=$($task.State)" 'INFO'
  try {
    Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
    $postState = (Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue).State
    Write-Log "    Disabled OK  ->  new State: $postState" 'SUCCESS'
  } catch {
    Write-Log "    FAILED to disable: $_" 'ERROR'
  }
}
Write-DefenderTasks "AFTER disable"
End-Stage "Scheduled task disabling"


Write-Host 'Cleaning Up...'
Start-Stage "Cleanup temp files"

try {
  Remove-Item "$env:TEMP\disableReg" -Recurse -Force -ErrorAction Stop
  Write-Log "  Removed: $env:TEMP\disableReg" 'SUCCESS'
} catch {
  Write-Log "  Could not remove $env:TEMP\disableReg : $_" 'WARN'
}

try {
  Remove-Item "$env:TEMP\DefeatDefend.ps1" -Force -ErrorAction Stop
  Write-Log "  Removed: $env:TEMP\DefeatDefend.ps1" 'SUCCESS'
} catch {
  Write-Log "  Could not remove $env:TEMP\DefeatDefend.ps1 : $_" 'WARN'
}

End-Stage "Cleanup"

# ════════════════════════════════════════════════════════════════════════════
# POST-RUN STATE CAPTURE
# ════════════════════════════════════════════════════════════════════════════
Write-Log "POST-RUN STATE" 'HEADER'
Write-ServiceSnapshot "POST-RUN"
Write-LogBlank
Write-ProcessSnapshot "POST-RUN"
Write-LogBlank
Write-DefenderRegistryState "POST-RUN"
Write-LogBlank
Write-DefenderFiles "POST-RUN"
Write-LogBlank
Write-DefenderTasks "POST-RUN"
Write-LogBlank
Write-DefenderEvents 20

# ════════════════════════════════════════════════════════════════════════════
# EXECUTION SUMMARY
# ════════════════════════════════════════════════════════════════════════════
$ScriptEndTime = Get-Date
$TotalElapsed  = $ScriptEndTime - $ScriptStartTime

Write-Log "EXECUTION SUMMARY" 'HEADER'
Write-Log "  Start time      : $($ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss.fff'))" 'DATA'
Write-Log "  End time        : $($ScriptEndTime.ToString('yyyy-MM-dd HH:mm:ss.fff'))" 'DATA'
Write-Log "  Total elapsed   : $($TotalElapsed.ToString('mm\:ss\.fff'))" 'DATA'
Write-Log "  Stages completed: $($script:StageNum)" 'DATA'
Write-LogBlank

if ($script:Errors.Count -gt 0) {
    Write-Log "  ERRORS ($($script:Errors.Count) total):" 'ERROR'
    foreach ($e in $script:Errors) { Write-Log "    $e" 'ERROR' }
} else {
    Write-Log "  ERRORS: none" 'SUCCESS'
}

Write-LogBlank

if ($script:Warnings.Count -gt 0) {
    Write-Log "  WARNINGS ($($script:Warnings.Count) total):" 'WARN'
    foreach ($w in $script:Warnings) { Write-Log "    $w" 'WARN' }
} else {
    Write-Log "  WARNINGS: none" 'SUCCESS'
}

Write-LogBlank

# Inner script logs — check again at summary time for anything that appeared late
$innerLogsLate = Get-ChildItem "$env:TEMP\DefeatDefend_inner_*.log" -ErrorAction SilentlyContinue
if ($innerLogsLate) {
    Write-Log "  Inner script log(s) present at summary time: $($innerLogsLate.Count)" 'INFO'
    foreach ($il in $innerLogsLate) {
        Write-Log "    $($il.FullName)  ($($il.Length) bytes)" 'DATA'
    }
} else {
    Write-Log "  No inner DefeatDefend_inner_*.log found at summary time." 'WARN'
}

Write-Log '' 'SEP'
Write-Log "  Full report saved to: $script:LogFile" 'SUCCESS'
Write-Log '' 'SEP'

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Log saved to: $script:LogFile" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
