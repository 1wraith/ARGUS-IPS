<#
.SYNOPSIS
    Registers ARGUS to start at boot on Windows.

.DESCRIPTION
    ARGUS is a console program, not a Windows service binary: it does not
    implement the Service Control Manager protocol, so `sc.exe create`
    pointed straight at argus.exe would produce a service the SCM kills
    after its start timeout. This script therefore registers a *scheduled
    task* that runs at system startup as SYSTEM.

    That is a fully supported Windows mechanism for a long-running
    background process, and for a sensor it is very close to equivalent:
    it starts at boot without a login, runs with the privileges packet
    capture needs, restarts on failure, and survives logoff. What it does
    not give you is `sc.exe stop` / `Get-Service` integration. If you need
    those, wrap argus.exe with NSSM (https://nssm.cc) or WinSW, both of
    which implement the SCM side for arbitrary console programs.

    Npcap must already be installed.

.PARAMETER ExePath
    Full path to argus.exe.

.PARAMETER ConfigPath
    Full path to argus.conf. ARGUS is started with -config and -no-stdout,
    so every setting — interfaces, rules, outputs — lives in that file.

.PARAMETER TaskName
    Name of the scheduled task. Defaults to "ARGUS".

.PARAMETER Uninstall
    Remove the task instead of creating it.

.EXAMPLE
    .\install-windows-service.ps1 -ExePath C:\argus\argus.exe -ConfigPath C:\argus\argus.conf

.EXAMPLE
    .\install-windows-service.ps1 -Uninstall
#>

[CmdletBinding()]
param(
    [string]$ExePath,
    [string]$ConfigPath,
    [string]$TaskName = "ARGUS",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must run from an elevated PowerShell session (packet capture and task registration both require it)."
    }
}

Assert-Administrator

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task '$TaskName'."
    } else {
        Write-Host "No scheduled task named '$TaskName'."
    }
    return
}

if (-not $ExePath)    { throw "-ExePath is required (full path to argus.exe)." }
if (-not $ConfigPath) { throw "-ConfigPath is required (full path to argus.conf)." }
if (-not (Test-Path -LiteralPath $ExePath))    { throw "No such file: $ExePath" }
if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "No such file: $ConfigPath" }

# Npcap is the capture backend; without it ARGUS starts and immediately
# fails to open any interface, which as a boot task means a silent
# non-sensor. Better to say so now.
if (-not (Get-Service -Name npcap -ErrorAction SilentlyContinue)) {
    Write-Warning "The Npcap service was not found. ARGUS cannot capture without it: https://npcap.com/"
}

# -no-stdout because a task has no console to write to; every alert goes
# to the sinks the config file names. Verify at least one is configured.
$configText = Get-Content -LiteralPath $ConfigPath -Raw
if ($configText -notmatch '(?m)^\s*(logfile|alert-output|syslog)\s*=') {
    Write-Warning "$ConfigPath names no logfile, alert-output or syslog. With -no-stdout, alerts would have nowhere to go and ARGUS will refuse to start."
}

$workingDir = Split-Path -Parent $ExePath
$action = New-ScheduledTaskAction -Execute $ExePath `
    -Argument "-config `"$ConfigPath`" -no-stdout" `
    -WorkingDirectory $workingDir

$trigger = New-ScheduledTaskTrigger -AtStartup

# SYSTEM, because packet capture needs privileges no ordinary account
# has, and because the task must run with no user logged in.
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -DontStopOnIdleEnd `
    -StartWhenAvailable `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -RestartCount 3 `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Write-Host "Replacing existing task '$TaskName'."
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Register-ScheduledTask -TaskName $TaskName `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "ARGUS network intrusion detection system" | Out-Null

Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "Registered and started '$TaskName'."
Write-Host ""
Write-Host "  Status   Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo"
Write-Host "  Stop     Stop-ScheduledTask -TaskName $TaskName"
Write-Host "  Start    Start-ScheduledTask -TaskName $TaskName"
Write-Host "  Remove   .\install-windows-service.ps1 -Uninstall"
Write-Host ""
Write-Host "There is no SIGHUP on Windows. Rule and enrichment files are re-read"
Write-Host "automatically when they change on disk (see -reload-interval), and the"
Write-Host "alert log rotates itself when -log-max-size is set."
