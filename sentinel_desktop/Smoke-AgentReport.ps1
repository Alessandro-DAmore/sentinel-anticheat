Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$config = Get-Content -LiteralPath (Join-Path $root 'config.json') -Raw | ConvertFrom-Json

function Get-Sha256Text {
  param([string]$Text)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    return ([BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
  }
}

function New-EncryptedEnvelope {
  param($Payload, [string]$SharedSecret)
  $json = $Payload | ConvertTo-Json -Depth 20 -Compress
  $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
  $key = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($SharedSecret))
  $iv = New-Object byte[] 16
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)
  $aes = [System.Security.Cryptography.Aes]::Create()
  $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
  $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
  $aes.Key = $key
  $aes.IV = $iv
  $cipherBytes = $aes.CreateEncryptor().TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
  $aes.Dispose()
  $input = New-Object byte[] ($iv.Length + $cipherBytes.Length)
  [Array]::Copy($iv, 0, $input, 0, $iv.Length)
  [Array]::Copy($cipherBytes, 0, $input, $iv.Length, $cipherBytes.Length)
  $hmac = [System.Security.Cryptography.HMACSHA256]::new($key)
  $tag = $hmac.ComputeHash($input)
  $hmac.Dispose()
  return @{
    encrypted = $true
    alg = 'AES-256-CBC-HMAC-SHA256'
    iv = [Convert]::ToBase64String($iv)
    ciphertext = [Convert]::ToBase64String($cipherBytes)
    hmac = [Convert]::ToBase64String($tag)
  }
}

function Invoke-SentinelJson {
  param([string]$Path, $Body)
  $headers = @{
    'Content-Type' = 'application/json'
    'X-Sentinel-Key' = $config.agentKey
  }
  $json = $Body | ConvertTo-Json -Depth 30 -Compress
  $lastError = $null
  for ($attempt = 1; $attempt -le 2; $attempt++) {
    try {
      return Invoke-RestMethod -Uri (($config.cloudEndpoint.TrimEnd('/')) + $Path) -Method Post -Headers $headers -Body $json -TimeoutSec 60 -DisableKeepAlive
    } catch {
      $lastError = $_
      if ($attempt -lt 2) {
        Start-Sleep -Milliseconds 500
      }
    }
  }
  throw $lastError
}

$machine = Get-Sha256Text ('sentinel:machine:smoke:' + [Environment]::MachineName)
$session = Invoke-SentinelJson -Path '/v1/agent/connect' -Body @{
  licenseKey = $config.licenseKey
  appVersion = $config.version
  machineFingerprint = $machine
}

$report = [ordered]@{
  reportId = [guid]::NewGuid().ToString()
  generatedAt = (Get-Date).ToUniversalTime().ToString('o')
  app = @{ name = $config.appName; version = $config.version; scanMode = 'smoke'; signatureVersion = 'smoke' }
  identity = @{
    machineFingerprint = $machine
    userFingerprint = Get-Sha256Text ('sentinel:user:smoke')
    publicIp = $session.publicIp
    localIps = @('127.0.0.1')
    hostNameHash = Get-Sha256Text ('sentinel:host:smoke')
  }
  summary = @{ highestSeverity = 'high'; findingCount = 1; suspicious = $true; stats = @{ processes = 0; services = 0; drivers = 0; filesVisited = 1; filesHashed = 1; fileErrors = 0 } }
  findings = @(@{ type = 'file'; severity = 'high'; signal = 'smoke-cheat'; reason = 'Smoke test suspicious file'; path = '%USERPROFILE%\\Downloads\\smoke-cheat.exe'; sha256 = ('a' * 64); size = 1234 })
}

$response = Invoke-SentinelJson -Path '/v1/agent/report' -Body @{
  licenseKey = $config.licenseKey
  machineFingerprint = $machine
  envelope = New-EncryptedEnvelope -Payload $report -SharedSecret $config.sharedSecret
}

$response | ConvertTo-Json -Depth 10
