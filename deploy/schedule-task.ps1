<#
.SYNOPSIS
    Registers a Windows Scheduled Task for Sloth SOC nightly analysis.
.DESCRIPTION
    Creates a daily scheduled task running at 06:00 UTC (or local time) to execute
    the Sloth SOC digest pipeline.
#>

param(
    [string]$TaskName = "SlothSOC-DailyDigest",
    [string]$PythonPath = "$PSScriptRoot\..\.venv\Scripts\python.exe",
    [string]$WorkingDir = "$PSScriptRoot\..",
    [string]$ConfigPath = "$PSScriptRoot\..\config.yaml",
    [string]$OutDir = "$PSScriptRoot\..\digests",
    [string]$DailyTime = "06:00"
)

$Action = New-ScheduledTaskAction -Execute $PythonPath -Argument "-m sloth_soc.cli run --config `"$ConfigPath`" --out `"$OutDir`"" -WorkingDirectory $WorkingDir
$Trigger = New-ScheduledTaskTrigger -Daily -At $DailyTime
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Description "Sloth SOC Nightly Security Log Digest Generator" -Force

Write-Host "Successfully registered scheduled task: $TaskName to run daily at $DailyTime" -ForegroundColor Green
