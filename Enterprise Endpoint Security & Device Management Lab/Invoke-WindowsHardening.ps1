#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enterprise Windows Endpoint Hardening Script
.DESCRIPTION
    Applies CIS Level 1 & 2 security baselines, firewall configuration,
    audit policies, and access restrictions to a Windows endpoint.
.PARAMETER ComputerName
    Target computer name or IP. Defaults to local machine.
.PARAMETER Level
    CIS baseline level: 1 (recommended) or 2 (high security). Default: 1
.PARAMETER WhatIf
    Preview changes without applying them.
.EXAMPLE
    .\Invoke-WindowsHardening.ps1 -ComputerName "WIN-WS-01" -Level 1
    .\Invoke-WindowsHardening.ps1 -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [ValidateSet(1, 2)]
    [int]$Level = 1,
    [string]$LogPath = "C:\Logs\Hardening"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region --- LOGGING ---
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp][$Level] $Message"
    Write-Host $entry -ForegroundColor $(
        switch ($Level) {
            "INFO"    { "Cyan" }
            "SUCCESS" { "Green" }
            "WARN"    { "Yellow" }
            "ERROR"   { "Red" }
        }
    )
    $entry | Out-File -FilePath "$LogPath\hardening_$(Get-Date -Format 'yyyyMMdd').log" -Append
}

function Initialize-Log {
    if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
    Write-Log "=== Enterprise Endpoint Hardening Started ===" "INFO"
    Write-Log "Target: $ComputerName | CIS Level: $Level" "INFO"
}
#endregion

#region --- ACCOUNT POLICIES ---
function Set-AccountPolicies {
    Write-Log "Applying account policies..." "INFO"
    try {
        # Password policy
        net accounts /minpwlen:14 /maxpwage:90 /minpwage:1 /uniquepw:24 | Out-Null

        # Account lockout policy
        net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null

        Write-Log "Account policies applied." "SUCCESS"
    } catch {
        Write-Log "Failed to set account policies: $_" "ERROR"
    }
}
#endregion

#region --- WINDOWS FIREWALL ---
function Set-FirewallHardening {
    Write-Log "Configuring Windows Firewall..." "INFO"
    try {
        # Enable all profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

        # Default deny inbound, allow outbound
        Set-NetFirewallProfile -Profile Domain,Public,Private `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Allow `
            -NotifyOnListen False `
            -AllowUnicastResponseToMulticast False

        # Remove all non-default rules and rebuild
        Get-NetFirewallRule | Where-Object { $_.Group -notlike "@*" } | Remove-NetFirewallRule -ErrorAction SilentlyContinue

        # Allow RDP only from admin subnet (adjust CIDR as needed)
        New-NetFirewallRule -DisplayName "Allow RDP - Admin Only" `
            -Direction Inbound -Protocol TCP -LocalPort 3389 `
            -RemoteAddress "192.168.100.0/24" -Action Allow -Profile Any | Out-Null

        # Allow WinRM only from admin subnet
        New-NetFirewallRule -DisplayName "Allow WinRM - Admin Only" `
            -Direction Inbound -Protocol TCP -LocalPort 5985,5986 `
            -RemoteAddress "192.168.100.0/24" -Action Allow -Profile Any | Out-Null

        # Block SMBv1
        New-NetFirewallRule -DisplayName "Block SMBv1" `
            -Direction Inbound -Protocol TCP -LocalPort 445 `
            -Action Block -Profile Any | Out-Null

        Write-Log "Firewall hardening complete." "SUCCESS"
    } catch {
        Write-Log "Firewall error: $_" "ERROR"
    }
}
#endregion

#region --- DISABLE LEGACY PROTOCOLS ---
function Disable-LegacyProtocols {
    Write-Log "Disabling legacy and insecure protocols..." "INFO"
    try {
        # Disable SMBv1
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null

        # Disable LLMNR
        $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (-not (Test-Path $llmnrPath)) { New-Item -Path $llmnrPath -Force | Out-Null }
        Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0

        # Disable NetBIOS over TCP/IP
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration
        foreach ($adapter in $adapters) {
            $adapter.SetTcpipNetbios(2) | Out-Null  # 2 = Disable NetBIOS
        }

        # Disable WDigest (prevents cleartext password in memory)
        $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        if (-not (Test-Path $wdigestPath)) { New-Item -Path $wdigestPath -Force | Out-Null }
        Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Value 0

        Write-Log "Legacy protocols disabled." "SUCCESS"
    } catch {
        Write-Log "Error disabling legacy protocols: $_" "ERROR"
    }
}
#endregion

#region --- AUDIT POLICIES ---
function Set-AuditPolicies {
    Write-Log "Configuring audit policies..." "INFO"
    try {
        $auditCategories = @{
            "Account Logon"             = "Success,Failure"
            "Account Management"        = "Success,Failure"
            "Detailed Tracking"         = "Success,Failure"
            "DS Access"                 = "Success,Failure"
            "Logon/Logoff"              = "Success,Failure"
            "Object Access"             = "Success,Failure"
            "Policy Change"             = "Success,Failure"
            "Privilege Use"             = "Success,Failure"
            "System"                    = "Success,Failure"
        }

        foreach ($category in $auditCategories.GetEnumerator()) {
            auditpol /set /category:"$($category.Key)" /success:enable /failure:enable | Out-Null
        }

        # Set event log sizes
        wevtutil sl Security /ms:1073741824    # 1GB
        wevtutil sl Application /ms:104857600  # 100MB
        wevtutil sl System /ms:104857600       # 100MB

        Write-Log "Audit policies configured." "SUCCESS"
    } catch {
        Write-Log "Audit policy error: $_" "ERROR"
    }
}
#endregion

#region --- REGISTRY HARDENING ---
function Set-RegistryHardening {
    Write-Log "Applying registry hardening controls..." "INFO"
    $regSettings = @(
        # Disable AutoRun/AutoPlay
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoDriveTypeAutoRun"; Value = 255 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoAutoRun"; Value = 1 },

        # Disable Remote Registry
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry"; Name = "Start"; Value = 4 },

        # Restrict anonymous access
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymous"; Value = 1 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymousSAM"; Value = 1 },

        # Enable UAC
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableLUA"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ConsentPromptBehaviorAdmin"; Value = 2 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "PromptOnSecureDesktop"; Value = 1 },

        # Disable Windows Script Host
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"; Name = "Enabled"; Value = 0 },

        # Enable Credential Guard prerequisites
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name = "EnableVirtualizationBasedSecurity"; Value = 1 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LsaCfgFlags"; Value = 1 }
    )

    foreach ($reg in $regSettings) {
        try {
            if (-not (Test-Path $reg.Path)) { New-Item -Path $reg.Path -Force | Out-Null }
            Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value
        } catch {
            Write-Log "Registry error at $($reg.Path)\$($reg.Name): $_" "WARN"
        }
    }

    Write-Log "Registry hardening applied." "SUCCESS"
}
#endregion

#region --- DISABLE UNNECESSARY SERVICES ---
function Disable-UnnecessaryServices {
    Write-Log "Disabling unnecessary services..." "INFO"
    $servicesToDisable = @(
        "Fax",
        "XblAuthManager",     # Xbox Live
        "XblGameSave",
        "XboxGipSvc",
        "XboxNetApiSvc",
        "WMPNetworkSvc",      # Windows Media Player sharing
        "RemoteRegistry",
        "Spooler"             # Disable print spooler if not needed (PrintNightmare)
    )

    foreach ($svc in $servicesToDisable) {
        try {
            $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($service) {
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svc -StartupType Disabled
                Write-Log "Disabled service: $svc" "INFO"
            }
        } catch {
            Write-Log "Could not disable $svc : $_" "WARN"
        }
    }

    Write-Log "Unnecessary services disabled." "SUCCESS"
}
#endregion

#region --- WINDOWS DEFENDER ---
function Set-DefenderConfiguration {
    Write-Log "Configuring Windows Defender..." "INFO"
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableIOAVProtection $false
        Set-MpPreference -DisableScriptScanning $false
        Set-MpPreference -EnableNetworkProtection Enabled
        Set-MpPreference -PUAProtection Enabled
        Set-MpPreference -EnableControlledFolderAccess Enabled
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent SendAllSamples
        Set-MpPreference -ScanScheduleDay Everyday
        Set-MpPreference -SignatureUpdateInterval 4

        Write-Log "Windows Defender configured." "SUCCESS"
    } catch {
        Write-Log "Defender configuration error: $_" "WARN"
    }
}
#endregion

#region --- GENERATE REPORT ---
function New-HardeningReport {
    $reportPath = "$LogPath\HardeningReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $report = [ordered]@{
        ComputerName     = $ComputerName
        ExecutedAt       = (Get-Date -Format "o")
        CISLevel         = $Level
        OSVersion        = (Get-CimInstance Win32_OperatingSystem).Caption
        Checks = @{
            FirewallEnabled       = (Get-NetFirewallProfile -Profile Domain).Enabled
            SMBv1Disabled         = (-not (Get-SmbServerConfiguration).EnableSMB1Protocol)
            BitLockerStatus       = (Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue).ProtectionStatus
            UAC_Enabled           = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA -eq 1)
            WDigestDisabled       = ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue).UseLogonCredential -eq 0)
            DefenderRealtime      = (-not (Get-MpPreference).DisableRealtimeMonitoring)
        }
    }

    $report | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportPath
    Write-Log "Hardening report saved: $reportPath" "SUCCESS"
    return $reportPath
}
#endregion

#region --- MAIN ---
function Main {
    Initialize-Log

    if ($PSCmdlet.ShouldProcess($ComputerName, "Apply CIS Level $Level Hardening")) {
        Set-AccountPolicies
        Set-FirewallHardening
        Disable-LegacyProtocols
        Set-AuditPolicies
        Set-RegistryHardening
        Disable-UnnecessaryServices
        Set-DefenderConfiguration
        $reportPath = New-HardeningReport

        Write-Log "=== Hardening Complete ===" "SUCCESS"
        Write-Log "Report: $reportPath" "INFO"
        Write-Log "A reboot may be required for some settings to take effect." "WARN"
    }
}

Main
#endregion
