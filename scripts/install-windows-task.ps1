<#
.SYNOPSIS
  Registers (or removes) a Windows Scheduled Task that starts the Gmail MCP
  server at boot and restarts it if it crashes.

.DESCRIPTION
  Run from an elevated PowerShell prompt inside the repository:

      .\scripts\install-windows-task.ps1              # run as the current user (prompts for password)
      .\scripts\install-windows-task.ps1 -AsSystem    # run as LOCAL SYSTEM (no password needed)
      .\scripts\install-windows-task.ps1 -Uninstall   # remove the task

  The task runs:  node --env-file=.env dist\index.js
  with the repo as working directory and appends output to logs\server.log.

  Prerequisites: `npm ci`, `npm run build`, and a populated .env in the repo root.
#>
[CmdletBinding()]
param(
  [string]$TaskName = "Gmail MCP Server",
  [switch]$AsSystem,
  [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ($Uninstall) {
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'."
  } else {
    Write-Host "Task '$TaskName' does not exist."
  }
  return
}

# --- sanity checks -----------------------------------------------------------

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this script from an elevated (Administrator) PowerShell." }

$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { throw "node.exe not found on PATH." }

$nodeMajor = [int]((& $node -v).TrimStart("v").Split(".")[0])
if ($nodeMajor -lt 20) { throw "Node 20.6+ is required for --env-file (found $(& $node -v))." }

foreach ($required in @("dist\index.js", ".env")) {
  if (-not (Test-Path (Join-Path $repo $required))) {
    throw "Missing $required in $repo. Run 'npm ci', 'npm run build' and create .env first."
  }
}

$logDir = Join-Path $repo "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logFile = Join-Path $logDir "server.log"

# --- task definition ---------------------------------------------------------

# cmd.exe wrapper so stdout/stderr land in a log file (Task Scheduler discards them otherwise).
$cmdLine = "/c `"`"$node`" --env-file=.env dist\index.js >> `"$logFile`" 2>&1`""
$action = New-ScheduledTaskAction -Execute "$env:ComSpec" -Argument $cmdLine -WorkingDirectory $repo

$trigger = New-ScheduledTaskTrigger -AtStartup

# ExecutionTimeLimit 0 = never kill the task (the default stops it after 3 days).
$settings = New-ScheduledTaskSettingsSet `
  -ExecutionTimeLimit ([TimeSpan]::Zero) `
  -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
  -MultipleInstances IgnoreNew `
  -StartWhenAvailable `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

if ($AsSystem) {
  $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  $registerArgs = @{ Principal = $principal }
} else {
  $user = "$env:USERDOMAIN\$env:USERNAME"
  Write-Host "The task will run as $user whether or not anyone is logged on."
  $cred = Get-Credential -UserName $user -Message "Password for $user (stored by Task Scheduler)"
  $registerArgs = @{
    User     = $user
    Password = $cred.GetNetworkCredential().Password
    RunLevel = "Highest"
  }
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
  -Description "Starts the Gmail MCP server at boot ($repo)" @registerArgs | Out-Null

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3

$task = Get-ScheduledTask -TaskName $TaskName
Write-Host ""
Write-Host "Registered '$TaskName' (state: $($task.State))."
Write-Host "  Working dir: $repo"
Write-Host "  Log file:    $logFile"
Write-Host ""
Write-Host "Useful commands:"
Write-Host "  Get-Content `"$logFile`" -Tail 20 -Wait      # follow the log"
Write-Host "  Stop-ScheduledTask -TaskName `"$TaskName`"    # stop"
Write-Host "  Start-ScheduledTask -TaskName `"$TaskName`"   # start"
Write-Host "  .\scripts\install-windows-task.ps1 -Uninstall  # remove"
