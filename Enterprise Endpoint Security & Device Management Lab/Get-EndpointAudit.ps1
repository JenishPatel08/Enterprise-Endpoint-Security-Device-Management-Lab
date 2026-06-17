#Requires -Version 5.1
<#
.SYNOPSIS
    Enterprise Endpoint Audit Script
.DESCRIPTION
    Performs a comprehensive security audit of a Windows endpoint including:
    system info, user accounts, services, firewall, patches, open ports,
    running processes, and startup items.
.PARAMETER Target
    Single hostname, IP, or subnet CIDR (e.g. 192.168.100.0/24)
.PARAMETER ExportPath
    Path to export JSON audit results. Default: .\AuditReports\
.PARAMETER Credential
    PSCredential for remote connections. Omit for local.
.EXAMPLE
    .\Get-EndpointAudit.ps1 -Target "WIN-WS-01" -ExportPath "C:\Reports\"
    .\Get-EndpointAudit.ps1 -Target "192.168.100.0/24"
#>

[CmdletBinding()]
param(
    [string]$Target      = $env:COMPUTERNAME,
    [string]$ExportPath  = ".\AuditReports\",
    [PSCredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null }

function Write-Log {
    param([string]$Msg, [string]$Lvl = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $color = switch($Lvl) { "SUCCESS"{"Green"} "WARN"{"Yellow"} "ERROR"{"Red"} default{"Cyan"} }
    Write-Host "[$ts] $Msg" -ForegroundColor $color
}

function Expand-CIDRToHosts {
    param([string]$CIDR)
    $parts = $CIDR.Split("/")
    $ip = [System.Net.IPAddress]::Parse($parts[0])
    $prefix = [int]$parts[1]
    $mask = [uint32]([Math]::Pow(2, 32) - [Math]::Pow(2, 32 - $prefix))
    $network = [uint32][System.Net.IPAddress]::NetworkToHostOrder([int]([System.Net.IPAddress]::Parse($parts[0]).Address)) -band $mask
    $hosts = [Math]::Pow(2, 32 - $prefix) - 2
    1..$hosts | ForEach-Object {
        $hostIP = $network + $_
        [System.Net.IPAddress]([System.Net.IPAddress]::HostToNetworkOrder([int]$hostIP)).ToString()
    }
}

function Get-SystemInfo {
    param([string]$Computer)
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Computer
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem  -ComputerName $Computer
    $bios = Get-CimInstance -ClassName Win32_BIOS          -ComputerName $Computer
    [ordered]@{
        Hostname        = $Computer
        OS              = $os.Caption
        OSVersion       = $os.Version
        OSArchitecture  = $os.OSArchitecture
        BuildNumber     = $os.BuildNumber
        LastBoot        = $os.LastBootUpTime
        Manufacturer    = $cs.Manufacturer
        Model           = $cs.Model
        RAM_GB          = [Math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        Domain          = $cs.Domain
        BIOSVersion     = $bios.SMBIOSBIOSVersion
        SerialNumber    = $bios.SerialNumber
    }
}

function Get-UserAccountAudit {
    param([string]$Computer)
    $users = Get-LocalUser -ErrorAction SilentlyContinue
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    $adminNames = $admins.Name | ForEach-Object { $_.Split("\")[-1] }

    $users | Select-Object @(
        "Name",
        "Enabled",
        "LastLogon",
        "PasswordLastSet",
        "PasswordExpires",
        "PasswordRequired",
        @{ Name = "IsAdmin"; Expression = { $adminNames -contains $_.Name } },
        @{ Name = "StaleAccount"; Expression = { $_.LastLogon -lt (Get-Date).AddDays(-90) -and $_.Enabled } }
    )
}

function Get-PatchStatus {
    param([string]$Computer)
    $hotfixes = Get-HotFix -ComputerName $Computer | 
        Sort-Object InstalledOn -Descending |
        Select-Object -First 20 HotFixID, Description, InstalledOn, InstalledBy

    $lastPatch = ($hotfixes | Select-Object -First 1).InstalledOn
    $daysSincePatch = if ($lastPatch) { ((Get-Date) - $lastPatch).Days } else { 999 }

    [ordered]@{
        LastPatchDate   = $lastPatch
        DaysSincePatch  = $daysSincePatch
        PatchStatus     = if ($daysSincePatch -le 30) { "Current" } elseif ($daysSincePatch -le 60) { "Warning" } else { "Critical" }
        RecentHotfixes  = $hotfixes
    }
}

function Get-FirewallStatus {
    param([string]$Computer)
    $profiles = Get-NetFirewallProfile -CimSession (New-CimSession -ComputerName $Computer -ErrorAction SilentlyContinue) -ErrorAction SilentlyContinue
    if (-not $profiles) {
        $profiles = Get-NetFirewallProfile
    }
    $profiles | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked
}

function Get-OpenPorts {
    param([string]$Computer)
    $commonPorts = @(21,22,23,25,53,80,110,135,139,143,443,445,3389,5985,5986,8080,8443)
    $openPorts = @()
    foreach ($port in $commonPorts) {
        $result = Test-NetConnection -ComputerName $Computer -Port $port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        if ($result.TcpTestSucceeded) {
            $openPorts += [PSCustomObject]@{
                Port    = $port
                Service = switch($port) {
                    21 {"FTP"} 22 {"SSH"} 23 {"Telnet"} 25 {"SMTP"} 53 {"DNS"}
                    80 {"HTTP"} 110 {"POP3"} 135 {"RPC"} 139 {"NetBIOS"} 143 {"IMAP"}
                    443 {"HTTPS"} 445 {"SMB"} 3389 {"RDP"} 5985 {"WinRM-HTTP"}
                    5986 {"WinRM-HTTPS"} 8080 {"HTTP-Alt"} 8443 {"HTTPS-Alt"}
                    default { "Unknown" }
                }
                Risk = switch($port) {
                    23 {"HIGH"} 21 {"MEDIUM"} 139 {"HIGH"} 445 {"MEDIUM"} 135 {"MEDIUM"} default {"LOW"}
                }
            }
        }
    }
    $openPorts
}

function Get-RunningProcesses {
    param([string]$Computer)
    Get-CimInstance Win32_Process -ComputerName $Computer |
        Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, @{
            Name = "Owner"; Expression = { ($_.GetOwner()).User }
        } | Sort-Object Name
}

function Get-StartupItems {
    param([string]$Computer)
    $startupPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )
    $items = @()
    foreach ($path in $startupPaths) {
        try {
            $reg = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($reg) {
                $reg.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                    $items += [PSCustomObject]@{ RegistryPath = $path; Name = $_.Name; Command = $_.Value }
                }
            }
        } catch {}
    }
    $items
}

function Get-BitLockerStatus {
    param([string]$Computer)
    try {
        $vols = Get-BitLockerVolume -ErrorAction SilentlyContinue
        $vols | Select-Object MountPoint, ProtectionStatus, EncryptionMethod, EncryptionPercentage, VolumeStatus
    } catch {
        [PSCustomObject]@{ Error = "Could not retrieve BitLocker status" }
    }
}

function Invoke-EndpointAudit {
    param([string]$Computer)
    Write-Log "Auditing: $Computer" "INFO"

    $audit = [ordered]@{
        AuditDate       = Get-Date -Format "o"
        AuditedBy       = $env:USERNAME
        SystemInfo      = Get-SystemInfo       -Computer $Computer
        UserAccounts    = Get-UserAccountAudit -Computer $Computer
        PatchStatus     = Get-PatchStatus      -Computer $Computer
        FirewallStatus  = Get-FirewallStatus   -Computer $Computer
        OpenPorts       = Get-OpenPorts        -Computer $Computer
        RunningProcesses = Get-RunningProcesses -Computer $Computer
        StartupItems    = Get-StartupItems     -Computer $Computer
        BitLockerStatus = Get-BitLockerStatus  -Computer $Computer
    }

    # Risk scoring
    $riskScore = 0
    if ($audit.PatchStatus.DaysSincePatch -gt 60)  { $riskScore += 30 }
    if ($audit.PatchStatus.DaysSincePatch -gt 30)  { $riskScore += 10 }
    $highRiskPorts = $audit.OpenPorts | Where-Object { $_.Risk -eq "HIGH" }
    $riskScore += ($highRiskPorts.Count * 15)
    $staleAccounts = $audit.UserAccounts | Where-Object { $_.StaleAccount -eq $true }
    $riskScore += ($staleAccounts.Count * 5)
    if ($audit.BitLockerStatus -and $audit.BitLockerStatus.ProtectionStatus -ne "On") { $riskScore += 20 }

    $audit["RiskScore"]  = [Math]::Min($riskScore, 100)
    $audit["RiskRating"] = if ($riskScore -ge 60) { "HIGH" } elseif ($riskScore -ge 30) { "MEDIUM" } else { "LOW" }

    # Export
    $filename = "$ExportPath\Audit_${Computer}_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $audit | ConvertTo-Json -Depth 10 | Out-File -FilePath $filename -Encoding UTF8
    Write-Log "Audit saved: $filename [Risk: $($audit.RiskRating) ($($audit.RiskScore)/100)]" "SUCCESS"
    return $audit
}

# ---- MAIN ----
Write-Log "=== Enterprise Endpoint Audit ===" "INFO"

$targets = @()
if ($Target -match "^\d+\.\d+\.\d+\.\d+/\d+$") {
    Write-Log "Expanding CIDR: $Target" "INFO"
    $targets = Expand-CIDRToHosts -CIDR $Target | Where-Object {
        Test-Connection -ComputerName $_ -Count 1 -Quiet -ErrorAction SilentlyContinue
    }
} else {
    $targets = @($Target)
}

Write-Log "Targets to audit: $($targets.Count)" "INFO"

$allResults = @()
foreach ($t in $targets) {
    $allResults += Invoke-EndpointAudit -Computer $t
}

# Summary report
$summaryPath = "$ExportPath\AuditSummary_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$allResults | ForEach-Object {
    [PSCustomObject]@{
        Hostname   = $_.SystemInfo.Hostname
        OS         = $_.SystemInfo.OS
        RiskRating = $_.RiskRating
        RiskScore  = $_.RiskScore
        PatchStatus = $_.PatchStatus.PatchStatus
        OpenHighRiskPorts = ($_.OpenPorts | Where-Object { $_.Risk -eq "HIGH" }).Count
        StaleUsers = ($_.UserAccounts | Where-Object { $_.StaleAccount }).Count
        AuditDate  = $_.AuditDate
    }
} | Export-Csv -Path $summaryPath -NoTypeInformation

Write-Log "Summary CSV: $summaryPath" "SUCCESS"
Write-Log "Total endpoints audited: $($allResults.Count)" "INFO"
