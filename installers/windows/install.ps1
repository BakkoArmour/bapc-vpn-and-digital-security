<#
  BAPC endpoint agent installer (Windows).

  IMPORTANT: a plain Node.js process does not implement the Windows Service
  Control Manager handshake, so `New-Service -BinaryPathName "node.exe ..."`
  APPEARS to work but Windows kills the service almost immediately ("did not
  respond in a timely fashion"). This script therefore uses WinSW
  (https://github.com/winsw/winsw, MIT licensed) as the service wrapper —
  the same approach node-windows and most production Node-on-Windows
  deployments use. Download winsw-x64.exe yourself (this script does not
  fetch it) and place it next to this script as winsw.exe before running.

  Usage (elevated PowerShell): .\install.ps1 -RepoRoot C:\bapc-security
#>
param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [string]$ServiceName = "BapcSecurityAgent"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$winsw = Join-Path $scriptDir "winsw.exe"
if (-not (Test-Path $winsw)) {
  throw "winsw.exe not found next to install.ps1. Download it from https://github.com/winsw/winsw/releases and place it here first."
}
if (-not (Test-Path (Join-Path $RepoRoot "dist\src\runtime\agent.js"))) {
  throw "$RepoRoot\dist\src\runtime\agent.js not found — run 'npm run build' in $RepoRoot first."
}

$installDir = "C:\Program Files\BapcSecurityAgent"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item $winsw (Join-Path $installDir "$ServiceName.exe") -Force

$configXml = @"
<service>
  <id>$ServiceName</id>
  <name>BAPC VPN & Digital Security Agent</name>
  <description>Endpoint enrollment, posture reporting and policy enforcement agent.</description>
  <executable>node.exe</executable>
  <arguments>"$RepoRoot\dist\src\runtime\agent.js"</arguments>
  <workingdirectory>$RepoRoot</workingdirectory>
  <env name="NODE_ENV" value="production"/>
  <log mode="roll-daily"/>
  <onfailure action="restart" delay="5 sec"/>
</service>
"@
Set-Content -Path (Join-Path $installDir "$ServiceName.xml") -Value $configXml -Encoding UTF8

Push-Location $installDir
try {
  & ".\$ServiceName.exe" install
  Start-Service $ServiceName
} finally {
  Pop-Location
}

Write-Output "Installed and started service '$ServiceName'. Check status with: Get-Service $ServiceName"
