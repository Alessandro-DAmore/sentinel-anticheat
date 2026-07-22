param(
  [Parameter(Mandatory = $true)][string]$EncryptedReportPath,
  [Parameter(Mandatory = $true)][string]$PrivateKeyPath,
  [string]$OutputPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertFrom-Base64Bytes {
  param([string]$Value)
  return [Convert]::FromBase64String($Value)
}

$package = Get-Content -LiteralPath $EncryptedReportPath -Raw | ConvertFrom-Json
$envelope = $package.encryptedReport
if ($null -eq $envelope -or $envelope.mode -ne 'zero_knowledge_v2') {
  throw 'Unsupported Sentinel report envelope.'
}

$privateXml = Get-Content -LiteralPath $PrivateKeyPath -Raw
$rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
try {
  $rsa.PersistKeyInCsp = $false
  $rsa.FromXmlString($privateXml)
  $keyMaterial = $rsa.Decrypt((ConvertFrom-Base64Bytes $envelope.wrappedKey), $true)
} finally {
  $rsa.Dispose()
}

if ($keyMaterial.Length -ne 64) {
  throw 'Invalid Sentinel key material.'
}

$aesKey = New-Object byte[] 32
$hmacKey = New-Object byte[] 32
[Array]::Copy($keyMaterial, 0, $aesKey, 0, 32)
[Array]::Copy($keyMaterial, 32, $hmacKey, 0, 32)

$iv = ConvertFrom-Base64Bytes $envelope.iv
$ciphertext = ConvertFrom-Base64Bytes $envelope.ciphertext
$expected = ConvertFrom-Base64Bytes $envelope.hmac

$hmacInput = New-Object byte[] ($iv.Length + $ciphertext.Length)
[Array]::Copy($iv, 0, $hmacInput, 0, $iv.Length)
[Array]::Copy($ciphertext, 0, $hmacInput, $iv.Length, $ciphertext.Length)
$hmac = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
try {
  $actual = $hmac.ComputeHash($hmacInput)
} finally {
  $hmac.Dispose()
}

if ($actual.Length -ne $expected.Length) {
  throw 'Invalid report HMAC.'
}
for ($i = 0; $i -lt $actual.Length; $i++) {
  if ($actual[$i] -ne $expected[$i]) {
    throw 'Invalid report HMAC.'
  }
}

$aes = [System.Security.Cryptography.Aes]::Create()
try {
  $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
  $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
  $aes.Key = $aesKey
  $aes.IV = $iv
  $decryptor = $aes.CreateDecryptor()
  $plainBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
} finally {
  $aes.Dispose()
}

$json = [System.Text.Encoding]::UTF8.GetString($plainBytes)
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
  $OutputPath = [IO.Path]::ChangeExtension($EncryptedReportPath, '.decrypted.json')
}

$json | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Get-Item -LiteralPath $OutputPath | Select-Object FullName, Length, LastWriteTime
