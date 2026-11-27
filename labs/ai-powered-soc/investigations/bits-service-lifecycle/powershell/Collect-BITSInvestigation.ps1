# BITS service lifecycle evidence collector
# Read-only: does not change services, registry values, BITS jobs, or endpoint configuration.
# Intentionally does not call Get-BitsTransfer.

[CmdletBinding()]
param(
    [ValidateRange(1,720)][int]$Hours = 24,
    [ValidateRange(5,600)][int]$CorrelationSeconds = 60,
    [string]$OutputRoot = 'C:\CyberLab\Evidence'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$now = Get-Date
$since = $now.AddHours(-$Hours)
$stamp = $now.ToString('yyyyMMdd_HHmmss')
$outDir = Join-Path $OutputRoot "BITS_Investigation_$stamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

function Get-SafeEvents {
    param([string]$LogName, [int[]]$Id, [datetime]$StartTime, [datetime]$EndTime = (Get-Date))
    try {
        @(Get-WinEvent -FilterHashtable @{
            LogName = $LogName; Id = $Id; StartTime = $StartTime; EndTime = $EndTime
        } -ErrorAction Stop)
    } catch {
        Write-Warning "Could not query $LogName (IDs $($Id -join ',')): $($_.Exception.Message)"
        @()
    }
}

function Convert-EventRecord {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)
    [xml]$xml = $Event.ToXml()
    $fields = [ordered]@{}
    foreach ($node in @($xml.Event.EventData.Data)) {
        if ($null -eq $node) { continue }
        $name = [string]$node.GetAttribute('Name')
        if (-not [string]::IsNullOrWhiteSpace($name)) { $fields[$name] = [string]$node.InnerText }
    }
    [PSCustomObject]@{
        TimeCreated = $Event.TimeCreated.ToString('o')
        RecordId = $Event.RecordId
        Id = $Event.Id
        Provider = $Event.ProviderName
        MachineName = $Event.MachineName
        Fields = [PSCustomObject]$fields
        Message = $Event.Message
        Xml = $Event.ToXml()
    }
}

Write-Host "BITS investigation: $($since.ToString('o')) to $($now.ToString('o'))"
Write-Host "Output: $outDir"

# Windows System Event ID 7040 for BITS.
$systemEvents = Get-SafeEvents -LogName 'System' -Id 7040 -StartTime $since -EndTime $now
$bits7040Events = @($systemEvents | Where-Object {
    $_.Message -match '(?i)Background Intelligent Transfer Service|\bBITS\b'
} | Sort-Object TimeCreated)
$bits7040 = @($bits7040Events | ForEach-Object { Convert-EventRecord $_ })

# Sysmon Event ID 13 for the BITS Start registry value.
$sysmonLog = 'Microsoft-Windows-Sysmon/Operational'
$sysmon13Events = Get-SafeEvents -LogName $sysmonLog -Id 13 -StartTime $since -EndTime $now
$bits13Events = @($sysmon13Events | Where-Object {
    $_.Message -match '(?i)\CurrentControlSet\Services\BITS\Start'
} | Sort-Object TimeCreated)
$bits13 = @($bits13Events | ForEach-Object { Convert-EventRecord $_ })

# Sysmon Event ID 1 process creation around each 7040 event.
$processMap = @{}
foreach ($change in $bits7040Events) {
    $from = $change.TimeCreated.AddSeconds(-$CorrelationSeconds)
    $to = $change.TimeCreated.AddSeconds($CorrelationSeconds)
    foreach ($event in (Get-SafeEvents -LogName $sysmonLog -Id 1 -StartTime $from -EndTime $to)) {
        $key = "$($event.MachineName):$($event.RecordId)"
        if (-not $processMap.ContainsKey($key)) {
            $processMap[$key] = [PSCustomObject]@{
                Correlated7040Time = $change.TimeCreated.ToString('o')
                WindowStart = $from.ToString('o')
                WindowEnd = $to.ToString('o')
                Event = Convert-EventRecord $event
            }
        }
    }
}
$processes = @($processMap.Values | Sort-Object { $_.Event.TimeCreated })

# Security 4688 and PowerShell 4104 near each BITS change, where available.
$security4688 = @()
$powerShell4104 = @()
foreach ($change in $bits7040Events) {
    $from = $change.TimeCreated.AddSeconds(-$CorrelationSeconds)
    $to = $change.TimeCreated.AddSeconds($CorrelationSeconds)
    foreach ($event in (Get-SafeEvents -LogName 'Security' -Id 4688 -StartTime $from -EndTime $to)) {
        $security4688 += Convert-EventRecord $event
    }
    foreach ($event in (Get-SafeEvents -LogName 'Microsoft-Windows-PowerShell/Operational' -Id 4104 -StartTime $from -EndTime $to)) {
        $powerShell4104 += Convert-EventRecord $event
    }
}

# Current BITS service and registry state (read-only).
$serviceState = @(Get-CimInstance Win32_Service -Filter "Name='BITS'" |
    Select-Object Name, State, StartMode, StartName, PathName)

$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\BITS'
$reg = Get-ItemProperty -LiteralPath $regPath
$delayed = $null
if ($reg.PSObject.Properties['DelayedAutoStart']) { $delayed = $reg.DelayedAutoStart }
$registryState = @([PSCustomObject]@{
    RegistryPath = 'HKLM\SYSTEM\CurrentControlSet\Services\BITS'
    Start = $reg.Start
    DelayedAutoStart = $delayed
})

# Discover available BITS-related event channels; do not enable or modify them.
$bitsChannels = @()
try {
    $bitsChannels = @(Get-WinEvent -ListLog '*BITS*' |
        Select-Object LogName, IsEnabled, RecordCount, LogMode, MaximumSizeInBytes)
} catch {
    Write-Warning "Could not enumerate BITS event channels: $($_.Exception.Message)"
}

$summary = [ordered]@{
    Hostname = $env:COMPUTERNAME
    CollectionTimeLocal = $now.ToString('o')
    LookbackStartLocal = $since.ToString('o')
    LookbackHours = $Hours
    CorrelationSeconds = $CorrelationSeconds
    Bits7040Count = $bits7040.Count
    BitsSysmon13Count = $bits13.Count
    ProcessesNear7040Count = $processes.Count
    Security4688Count = $security4688.Count
    PowerShell4104Count = $powerShell4104.Count
    Notes = @(
        'Read-only collection; no service, registry, or BITS job changes.',
        'Get-BitsTransfer is deliberately not invoked.',
        'Time proximity is correlation, not proof of causation.',
        'Security 4688 and 4657 depend on appropriate audit configuration.'
    )
    CurrentBitsService = $serviceState
    CurrentBitsRegistry = $registryState
    BitsRelatedEventChannels = $bitsChannels
    Bits7040 = $bits7040
    BitsSysmon13 = $bits13
    ProcessesNear7040 = $processes
    Security4688Near7040 = $security4688
    PowerShell4104Near7040 = $powerShell4104
}

$summary | ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath (Join-Path $outDir 'BITS_Investigation.json') -Encoding UTF8

$bits7040 | Export-Csv (Join-Path $outDir 'BITS_Event_7040.csv') -NoTypeInformation -Encoding UTF8
$bits13 | Export-Csv (Join-Path $outDir 'BITS_Sysmon_Event_13.csv') -NoTypeInformation -Encoding UTF8
$processes | Export-Csv (Join-Path $outDir 'Processes_Near_BITS_Changes.csv') -NoTypeInformation -Encoding UTF8
$security4688 | Export-Csv (Join-Path $outDir 'Security_4688_Near_BITS_Changes.csv') -NoTypeInformation -Encoding UTF8
$powerShell4104 | Export-Csv (Join-Path $outDir 'PowerShell_4104_Near_BITS_Changes.csv') -NoTypeInformation -Encoding UTF8
$serviceState | Export-Csv (Join-Path $outDir 'Current_BITS_Service.csv') -NoTypeInformation -Encoding UTF8
$registryState | Export-Csv (Join-Path $outDir 'Current_BITS_Registry.csv') -NoTypeInformation -Encoding UTF8
$bitsChannels | Export-Csv (Join-Path $outDir 'BITS_Event_Channels.csv') -NoTypeInformation -Encoding UTF8

# Hash the output exports; the manifest does not hash itself.
Get-ChildItem -LiteralPath $outDir -File |
    Get-FileHash -Algorithm SHA256 |
    Select-Object @{N='File';E={Split-Path $_.Path -Leaf}}, Algorithm, Hash |
    Export-Csv (Join-Path $outDir 'SHA256_Manifest.csv') -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "BITS Event 7040:        $($bits7040.Count)"
Write-Host "BITS Sysmon Event 13:   $($bits13.Count)"
Write-Host "Processes near changes: $($processes.Count)"
Write-Host "Security Event 4688:   $($security4688.Count)"
Write-Host "PowerShell Event 4104:  $($powerShell4104.Count)"
Write-Host "Evidence saved to: $outDir"
