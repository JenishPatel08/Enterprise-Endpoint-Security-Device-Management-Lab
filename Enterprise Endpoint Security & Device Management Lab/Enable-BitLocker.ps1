#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enterprise BitLocker Encryption Deployment Script
.DESCRIPTION
    Enables BitLocker AES-256 encryption on Windows endpoints.
    Backs up recovery keys to Active Directory or a secure file share.
.PARAMETER Drive
    Drive letter to encrypt. Default: C:
.PARAMETER BackupMethod
    Where to store recovery key: AD, File, or Both. Default: File
.PARAMETER RecoveryKeyPath
    UNC path or local path for recovery key backup. Default: C:\BitLockerKeys\
.EXAMPLE
    .\Enable-BitLocker.ps1 -Drive "C:" -BackupMethod AD
    .\Enable-BitLocker.ps1 -Drive "C:" -BackupMethod File -RecoveryKeyPath "\\fileserver\BitLockerKeys\"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Drive = "C:",
    [ValidateSet("AD", "File", "Both")]
    [string]$BackupMethod = "File",
    [string]$RecoveryKeyPath = "C:\BitLockerKeys\"
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Msg, [string]$Lvl = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch($Lvl) { "SUCCESS"{"Green"} "WARN"{"Yellow"} "ERROR"{"Red"} default{"Cyan"} }
    Write-Host "[$ts][$Lvl] $Msg" -ForegroundColor $color
}

function Test-TPM {
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    if (-not $tpm) {
        Write-Log "No TPM found. BitLocker will use password protector." "WARN"
        return $false
    }
    if (-not $tpm.TpmReady) {
        Write-Log "TPM not ready. Initializing..." "WARN"
        Initialize-Tpm -AllowClear -AllowPhysicalPresence | Out-Null
    }
    Write-Log "TPM Status: Ready=$($tpm.TpmReady), Present=$($tpm.TpmPresent)" "INFO"
    return $tpm.TpmReady
}

function Enable-BitLockerOnDrive {
    param([string]$DriveLetter)

    $blv = Get-BitLockerVolume -MountPoint $DriveLetter -ErrorAction SilentlyContinue
    if ($blv -and $blv.ProtectionStatus -eq "On") {
        Write-Log "BitLocker already ON for $DriveLetter" "SUCCESS"
        return $blv
    }

    $hasTpm = Test-TPM

    if ($hasTpm) {
        Write-Log "Enabling BitLocker with TPM + Recovery Password on $DriveLetter..." "INFO"
        Enable-BitLocker -MountPoint $DriveLetter `
            -EncryptionMethod Aes256 `
            -TpmProtector `
            -RecoveryPasswordProtector `
            -UsedSpaceOnly `
            -SkipHardwareTest | Out-Null
    } else {
        $securePass = Read-Host "Enter BitLocker password" -AsSecureString
        Enable-BitLocker -MountPoint $DriveLetter `
            -EncryptionMethod Aes256 `
            -PasswordProtector $securePass `
            -RecoveryPasswordProtector `
            -UsedSpaceOnly | Out-Null
    }

    return Get-BitLockerVolume -MountPoint $DriveLetter
}

function Backup-RecoveryKey {
    param($BitLockerVolume)

    $recoveryKeyProtector = $BitLockerVolume.KeyProtector | 
        Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } | 
        Select-Object -First 1

    if (-not $recoveryKeyProtector) {
        Write-Log "No recovery key protector found!" "ERROR"
        return
    }

    $recoveryKeyId = $recoveryKeyProtector.KeyProtectorId
    $recoveryKey   = $recoveryKeyProtector.RecoveryPassword
    $hostname      = $env:COMPUTERNAME

    if ($BackupMethod -in "File","Both") {
        if (-not (Test-Path $RecoveryKeyPath)) { New-Item -ItemType Directory -Path $RecoveryKeyPath -Force | Out-Null }
        $keyFile = Join-Path $RecoveryKeyPath "$hostname`_$($Drive.Replace(':',''))_RecoveryKey.txt"
        @"
Computer:     $hostname
Drive:        $Drive
Date:         $(Get-Date -Format 'o')
Key ID:       $recoveryKeyId
Recovery Key: $recoveryKey
"@ | Out-File -FilePath $keyFile -Encoding UTF8
        Write-Log "Recovery key saved to: $keyFile" "SUCCESS"
    }

    if ($BackupMethod -in "AD","Both") {
        try {
            Backup-BitLockerKeyProtector -MountPoint $Drive -KeyProtectorId $recoveryKeyId | Out-Null
            Write-Log "Recovery key backed up to Active Directory." "SUCCESS"
        } catch {
            Write-Log "AD backup failed (may not be domain-joined): $_" "WARN"
        }
    }
}

function Get-EncryptionStatus {
    param([string]$DriveLetter)
    $vol = Get-BitLockerVolume -MountPoint $DriveLetter
    [PSCustomObject]@{
        Computer          = $env:COMPUTERNAME
        Drive             = $DriveLetter
        ProtectionStatus  = $vol.ProtectionStatus
        EncryptionMethod  = $vol.EncryptionMethod
        EncryptionPercent = $vol.EncryptionPercentage
        VolumeStatus      = $vol.VolumeStatus
        KeyProtectors     = ($vol.KeyProtector.KeyProtectorType -join ", ")
    }
}

# ---- MAIN ----
Write-Log "=== BitLocker Deployment Script ===" "INFO"
Write-Log "Target Drive: $Drive | Backup: $BackupMethod" "INFO"

if ($PSCmdlet.ShouldProcess($Drive, "Enable BitLocker AES-256")) {
    $vol = Enable-BitLockerOnDrive -DriveLetter $Drive
    Backup-RecoveryKey -BitLockerVolume $vol
    $status = Get-EncryptionStatus -DriveLetter $Drive
    $status | Format-List
    Write-Log "BitLocker deployment complete." "SUCCESS"
}
