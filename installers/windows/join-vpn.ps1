<#
  BAPC VPN - join this Windows PC and connect it.

  Run from an elevated PowerShell ("Run as administrator"):
    powershell -ExecutionPolicy Bypass -File .\join-vpn.ps1 -InviteCode BAPC-XXXXXX-XXXXXX-XXXXXX-XXXXXX

  What it does:
    1. Installs WireGuard (the VPN engine) if it isn't already installed -
       the official, signature-checked installer from wireguard.com.
    2. Creates this PC's keys. The device identity key and the attestation
       key live inside the PC's TPM chip and can't be copied off it.
    3. Joins with the one-time invite code over HTTPS
       (POST /api/v1/devices/join, see src/application/device-join.ts),
       sending a TPM-signed attestation envelope (the format
       src/infrastructure/attestation/envelope.ts verifies).
    4. Installs the "BAPC" tunnel and checks traffic really goes through it.
       If no internet comes through, it switches the tunnel off again so the
       PC is never left offline.

  Re-running it after a successful join just reconnects (no new invite
  needed). To switch the VPN off:
    powershell -ExecutionPolicy Bypass -File .\join-vpn.ps1 -Disconnect
#>
param(
  [string]$InviteCode,
  [string]$ServerUrl = "https://vpn.bapc-headquarters.com",
  [switch]$Disconnect,
  # Testing aid: join and write the tunnel config, but don't install
  # anything (works without admin rights).
  [switch]$EnrollOnly,
  [string]$StateDir = "$env:ProgramData\BAPC\VPN"
)

$ErrorActionPreference = "Stop"
$TunnelName = "BAPC"
$ConfPath = Join-Path $StateDir "$TunnelName.conf"
$WgDir = Join-Path $env:ProgramFiles "WireGuard"
$WireGuardExe = Join-Path $WgDir "wireguard.exe"
$WgExe = Join-Path $WgDir "wg.exe"

function Say([string]$m) { Write-Host $m }
function Fail([string]$m) { Write-Host ""; Write-Host "Could not finish: $m" -ForegroundColor Red; exit 1 }

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $EnrollOnly -and -not $IsAdmin) {
  Fail "please open PowerShell with 'Run as administrator', then run this again."
}

if ($Disconnect) {
  if (Test-Path $WireGuardExe) { & $WireGuardExe /uninstalltunnelservice $TunnelName 2>$null }
  Say "BAPC VPN is off. Run this script again (without -Disconnect) to turn it back on."
  exit 0
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ---------- WireGuard ----------

function Install-WireGuard {
  if (Test-Path $WireGuardExe) { return }
  Say "Installing WireGuard (the VPN engine)..."
  $dir = Join-Path $env:TEMP ("bapc-wg-" + [guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Path $dir | Out-Null
  $installer = Join-Path $dir "wireguard-installer.exe"
  Invoke-WebRequest -UseBasicParsing -Uri "https://download.wireguard.com/windows-client/wireguard-installer.exe" -OutFile $installer
  $sig = Get-AuthenticodeSignature $installer
  if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "WireGuard LLC") {
    Fail "the WireGuard download didn't carry WireGuard's own digital signature, so it was not run."
  }
  # Not Start-Process -Wait: in Windows PowerShell that also waits for the
  # WireGuard window the installer opens afterwards, i.e. forever.
  $proc = Start-Process -FilePath $installer -PassThru
  $proc.WaitForExit()
  for ($i = 0; $i -lt 30 -and -not (Test-Path $WireGuardExe); $i++) { Start-Sleep -Seconds 2 }
  if (-not (Test-Path $WireGuardExe)) { Fail "WireGuard did not finish installing." }
  # The installer opens WireGuard's window; it isn't needed.
  Get-Process wireguard -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | Stop-Process -Force -ErrorAction SilentlyContinue
}

function New-WgKeyPair {
  if (Test-Path $WgExe) {
    $priv = (& $WgExe genkey).Trim()
    $pub = ($priv | & $WgExe pubkey).Trim()
    return @{ Private = $priv; Public = $pub }
  }
  if ($EnrollOnly -and (Get-Command node -ErrorAction SilentlyContinue)) {
    # Testing only (no WireGuard installed): same X25519 keys via Node.
    $js = "const {generateKeyPairSync:g}=require('crypto');const k=g('x25519');" +
          "const p=k.privateKey.export({format:'jwk'});" +
          "console.log(Buffer.from(p.d,'base64url').toString('base64')+' '+Buffer.from(p.x,'base64url').toString('base64'))"
    $parts = (& node -e $js).Trim().Split(" ")
    return @{ Private = $parts[0]; Public = $parts[1] }
  }
  Fail "WireGuard's key tool (wg.exe) was not found."
}

# ---------- DER / PEM helpers (Windows PowerShell 5.1 has no SPKI export) ----------

function Der([byte]$Tag, [byte[]]$Content) {
  $out = New-Object System.Collections.Generic.List[byte]
  $out.Add($Tag)
  $n = $Content.Length
  if ($n -lt 0x80) { $out.Add([byte]$n) }
  elseif ($n -lt 0x100) { $out.Add(0x81); $out.Add([byte]$n) }
  else { $out.Add(0x82); $out.Add([byte]($n -shr 8)); $out.Add([byte]($n -band 0xff)) }
  $out.AddRange($Content)
  return ,$out.ToArray()
}

function DerUInt([byte[]]$BigEndian) {
  $i = 0
  while ($i -lt $BigEndian.Length - 1 -and $BigEndian[$i] -eq 0) { $i++ }
  $list = New-Object System.Collections.Generic.List[byte]
  if ($BigEndian[$i] -band 0x80) { $list.Add(0) }
  for (; $i -lt $BigEndian.Length; $i++) { $list.Add($BigEndian[$i]) }
  return ,(Der 0x02 $list.ToArray())
}

# SubjectPublicKeyInfo PEM with "\n" line endings and 64-char lines - byte
# for byte what Node's createPublicKey().export({type:"spki",format:"pem"})
# produces, which is the identity-key string the server binds the
# attestation signature to.
function Get-SpkiPem($Rsa) {
  $p = $Rsa.ExportParameters($false)
  $rsaPub = Der 0x30 ([byte[]]((DerUInt $p.Modulus) + (DerUInt $p.Exponent)))
  [byte[]]$algId = 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
  $bitString = Der 0x03 ([byte[]](@([byte]0) + $rsaPub))
  $spki = Der 0x30 ([byte[]]($algId + $bitString))
  $b64 = [Convert]::ToBase64String($spki)
  $lines = for ($i = 0; $i -lt $b64.Length; $i += 64) { $b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) }
  return "-----BEGIN PUBLIC KEY-----`n" + ($lines -join "`n") + "`n-----END PUBLIC KEY-----`n"
}

# JSON.stringify for the plain strings that appear in the signed payload.
function JsonString([string]$s) {
  if ($s -match "[\x00-\x09\x0b-\x1f]") { throw "unexpected control character in signed payload" }
  return '"' + $s.Replace('\', '\\').Replace('"', '\"').Replace("`n", '\n') + '"'
}

function ToHex([byte[]]$b) { return -join ($b | ForEach-Object { $_.ToString("x2") }) }

# ---------- TPM keys ----------

$PlatformProvider = New-Object System.Security.Cryptography.CngProvider("Microsoft Platform Crypto Provider")

function New-TpmRsaKey([string]$Name) {
  $p = New-Object System.Security.Cryptography.CngKeyCreationParameters
  $p.Provider = $PlatformProvider
  $p.Parameters.Add((New-Object System.Security.Cryptography.CngProperty("Length", [BitConverter]::GetBytes(2048), [System.Security.Cryptography.CngPropertyOptions]::None)))
  if ($Name) {
    $p.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::OverwriteExistingKey
    if ($IsAdmin) { $p.KeyCreationOptions = $p.KeyCreationOptions -bor [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey }
  }
  $key = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa, $Name, $p)
  return New-Object System.Security.Cryptography.RSACng($key)
}

function Get-HardwareId {
  $uuid = (Get-CimInstance Win32_ComputerSystemProduct).UUID
  if ($uuid -and $uuid -notmatch "^(0|F|-)+$") { return $uuid.Trim() }
  return (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography").MachineGuid
}

# SHA-256 of the latest Windows measured-boot (TCG) log - the boot
# measurements the TPM's PCRs were extended with. Readable by
# administrators only; otherwise a clearly-labelled stand-in digest.
function Get-MeasuredBootDigest([string]$HardwareId) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $log = Get-ChildItem "$env:SystemRoot\Logs\MeasuredBoot\*.log" -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($log) { return ToHex ($sha.ComputeHash([IO.File]::ReadAllBytes($log.FullName))) }
  } catch {}
  return ToHex ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("no-measured-boot-log:" + $HardwareId)))
}

# ---------- join ----------

function Join-Vpn {
  if (-not $InviteCode) { $script:InviteCode = Read-Host "Paste your BAPC invite code" }
  if (-not $InviteCode) { Fail "an invite code is needed to join." }

  Say "Creating this PC's keys (stored in its TPM security chip)..."
  $wg = New-WgKeyPair
  $hardwareId = Get-HardwareId
  try {
    $identity = New-TpmRsaKey "BAPC-VPN-Identity"
    $ak = New-TpmRsaKey $null
  } catch {
    Fail "this PC's TPM security chip couldn't create a key ($($_.Exception.Message)). BAPC VPN needs a working TPM 2.0."
  }

  $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
    "CN=node-$hardwareId", $identity,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $csrDer = $req.CreateSigningRequest()

  $nonceBytes = New-Object byte[] 16
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonceBytes)
  $nonce = ToHex $nonceBytes
  $pcrDigest = Get-MeasuredBootDigest $hardwareId
  $akPem = Get-SpkiPem $ak

  # attestationSignedPayload (envelope.ts): canonical JSON, keys sorted.
  $payload = '{"hardwareId":' + (JsonString $hardwareId) +
             ',"identityPublicKeyPem":' + (JsonString (Get-SpkiPem $identity)) +
             ',"nonce":' + (JsonString $nonce) +
             ',"pcrDigest":' + (JsonString $pcrDigest) + '}'
  $signature = $ak.SignData([Text.Encoding]::UTF8.GetBytes($payload),
    [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $envelope = [ordered]@{
    provider = "windows-tpm"; nonce = $nonce; pcrDigest = $pcrDigest
    akPublicKeyPem = $akPem; signature = [Convert]::ToBase64String($signature)
  } | ConvertTo-Json -Compress
  try { $ak.Key.Delete() } catch {}

  $body = [ordered]@{
    inviteCode = $InviteCode.Trim(); hostname = $env:COMPUTERNAME; hardwareUuid = $hardwareId
    osSignature = "Windows_NT " + [Environment]::OSVersion.Version.ToString()
    wireguardPublicKey = $wg.Public; csrDer = [Convert]::ToBase64String($csrDer)
    attestationQuote = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($envelope))
  } | ConvertTo-Json -Compress

  Say "Joining BAPC VPN..."
  try {
    $resp = Invoke-RestMethod -Method Post -Uri "$($ServerUrl.TrimEnd('/'))/api/v1/devices/join" -ContentType "application/json" -Body $body -TimeoutSec 60
  } catch {
    $err = $_
    $msg = $err.Exception.Message
    try {
      $raw = $err.ErrorDetails.Message
      if (-not $raw -and $err.Exception.Response) {
        $raw = (New-Object IO.StreamReader($err.Exception.Response.GetResponseStream())).ReadToEnd()
      }
      if ($raw) { $msg = ($raw | ConvertFrom-Json).error.message }
    } catch {}
    Fail "the BAPC server refused to join this PC: $msg"
  }
  $d = $resp.data

  $conf = @(
    "[Interface]"
    "PrivateKey = $($wg.Private)"
    "Address = $($d.addresses.ipv4)/32, $($d.addresses.ipv6)/128"
    "DNS = $($d.dns -join ', ')"
    ""
    "[Peer]"
    "PublicKey = $($d.gateway.publicKey)"
    "AllowedIPs = $($d.gateway.allowedIps -join ', ')"
    "Endpoint = $($d.gateway.endpoint)"
    "PersistentKeepalive = $($d.gateway.keepaliveSeconds)"
  ) -join "`r`n"

  New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
  if ($IsAdmin) {
    # The private key is in here: SYSTEM and Administrators only.
    & icacls $StateDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
  }
  [IO.File]::WriteAllText($ConfPath, $conf + "`r`n", (New-Object Text.UTF8Encoding($false)))
  [IO.File]::WriteAllText((Join-Path $StateDir "client-cert.pem"), [string]$d.certificatePem)
  [IO.File]::WriteAllText((Join-Path $StateDir "node-id.txt"), [string]$d.nodeId)
  Say "Joined. This PC's VPN address is $($d.addresses.ipv4)."
}

# ---------- main ----------

if (-not $EnrollOnly) { Install-WireGuard }
if (Test-Path $ConfPath) { Say "This PC has already joined BAPC VPN - reconnecting." } else { Join-Vpn }
if ($EnrollOnly) { Say "Tunnel config written to $ConfPath (not installed: -EnrollOnly)."; exit 0 }

$endpointHost = ((Get-Content $ConfPath | Where-Object { $_ -like "Endpoint = *" }) -replace "^Endpoint = ", "") -replace ":\d+$", ""

Say "Connecting..."
& $WireGuardExe /uninstalltunnelservice $TunnelName 2>$null
Start-Sleep -Seconds 2
& $WireGuardExe /installtunnelservice $ConfPath

$publicIp = $null
for ($i = 0; $i -lt 15; $i++) {
  Start-Sleep -Seconds 2
  try { $publicIp = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 5).ip; break } catch {}
}
if (-not $publicIp) {
  & $WireGuardExe /uninstalltunnelservice $TunnelName 2>$null
  Fail "the VPN started but no internet came through it, so it was switched off again. Your internet is back to normal."
}
if ($publicIp -ne $endpointHost) {
  & $WireGuardExe /uninstalltunnelservice $TunnelName 2>$null
  Fail "internet traffic was not going through the VPN (seen as $publicIp), so it was switched off again."
}

Write-Host ""
Write-Host "BAPC VPN is ON. Your internet now goes through the BAPC server ($publicIp)." -ForegroundColor Green
Write-Host "It stays on after restarts. To switch it off: run this script with -Disconnect."
