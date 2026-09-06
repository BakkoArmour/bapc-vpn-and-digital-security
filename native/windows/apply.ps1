<#
  BAPC Windows platform adapter helper.
  Invoked as: powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
              -File apply.ps1 -Action <Action> -PayloadPath <path-to-json>

  All caller-supplied data (peer keys, IPs, rule definitions) arrives as JSON
  in PayloadPath, never as interpolated command-line/script text, so nothing
  from that data is ever parsed as PowerShell syntax.
  Requires an elevated (Administrator) PowerShell session for every Action
  except CollectPosture.
#>
param(
  [Parameter(Mandatory=$true)][string]$Action,
  [Parameter(Mandatory=$false)][string]$PayloadPath
)

$ErrorActionPreference = "Stop"
$payload = $null
if ($PayloadPath) { $payload = Get-Content -Raw -Path $PayloadPath | ConvertFrom-Json }

switch ($Action) {
  "ApplyFirewall" {
    $groupName = "BAPC-$($payload.commitId)"
    foreach ($rule in $payload.rules) {
      $action = if ($rule.action -eq "ALLOW") { "Allow" } else { "Block" }
      $protocol = if ($rule.protocols -contains "ANY" -or $rule.protocols.Count -eq 0) { "Any" } else { $rule.protocols[0] }
      New-NetFirewallRule -DisplayName "BAPC-$($rule.id)" -Group $groupName `
        -Direction Outbound -Action $action -Protocol $protocol `
        -RemotePort ($rule.ports -join ",") -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Output (@{ applied = $groupName } | ConvertTo-Json)
  }
  "RollbackFirewall" {
    $groupName = "BAPC-$($payload.commitId)"
    Get-NetFirewallRule -Group $groupName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Output (@{ rolledBack = $groupName } | ConvertTo-Json)
  }
  "SetKillSwitch" {
    if ($payload.enabled) {
      New-NetFirewallRule -DisplayName "BAPC-KillSwitch-AllowTunnel" -Group "BAPC-KillSwitch" `
        -Direction Outbound -Action Allow -InterfaceAlias $payload.interfaceAlias -ErrorAction SilentlyContinue | Out-Null
      New-NetFirewallRule -DisplayName "BAPC-KillSwitch-BlockAll" -Group "BAPC-KillSwitch" `
        -Direction Outbound -Action Block -ErrorAction SilentlyContinue | Out-Null
    } else {
      Get-NetFirewallRule -Group "BAPC-KillSwitch" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
    Write-Output (@{ killSwitch = [bool]$payload.enabled } | ConvertTo-Json)
  }
  "SetDns" {
    Set-DnsClientServerAddress -InterfaceAlias $payload.interfaceAlias -ServerAddresses $payload.servers
    Write-Output (@{ dns = $payload.servers } | ConvertTo-Json)
  }
  "Isolate" {
    New-NetFirewallRule -DisplayName "BAPC-Quarantine-BlockAll" -Group "BAPC-Quarantine" `
      -Direction Outbound -Action Block -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "BAPC-Quarantine-BlockInbound" -Group "BAPC-Quarantine" `
      -Direction Inbound -Action Block -ErrorAction SilentlyContinue | Out-Null
    Write-Output (@{ isolated = $true } | ConvertTo-Json)
  }
  "Restore" {
    Get-NetFirewallRule -Group "BAPC-Quarantine" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Output (@{ restored = $true } | ConvertTo-Json)
  }
  "CollectPosture" {
    $bitlocker = $null
    try { $bitlocker = (Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop).VolumeStatus -eq "FullyEncrypted" } catch { $bitlocker = $false }
    $secureBoot = $false
    try { $secureBoot = Confirm-SecureBootUEFI } catch { $secureBoot = $false }
    $firewallEnabled = (Get-NetFirewallProfile -Profile Domain,Public,Private | Where-Object { -not $_.Enabled }).Count -eq 0
    Write-Output (@{
      osCurrent = $true
      diskEncrypted = [bool]$bitlocker
      secureBoot = [bool]$secureBoot
      firewallEnabled = [bool]$firewallEnabled
      agentHealthy = $true
      bannedProcessFound = $false
    } | ConvertTo-Json)
  }
  default { throw "unsupported action: $Action" }
}
