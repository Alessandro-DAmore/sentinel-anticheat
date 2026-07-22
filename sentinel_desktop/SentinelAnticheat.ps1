param(
  [switch]$WorkerScan,
  [string]$WorkerProgressPath = '',
  [string]$WorkerResultPath = '',
  [string]$WorkerErrorPath = '',
  [string]$WorkerDiscordId = '',
  [string]$WorkerDiscordTag = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$Script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:ConfigPath = Join-Path $Script:Root 'config.json'
$Script:SignaturesPath = Join-Path $Script:Root 'signatures.json'
$Script:LogoPath = Join-Path $Script:Root 'assets\sentinel-logo.png'
$Script:IconPath = Join-Path $Script:Root 'assets\sentinel-app-icon.ico'
$Script:LogsPath = Join-Path $Script:Root 'logs'
$Script:ReportsPath = Join-Path $Script:Root 'reports'

function Read-JsonFile {
  param([Parameter(Mandatory = $true)][string]$Path)
  return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function ConvertTo-PlainObject {
  param($Value)

  if ($null -eq $Value) { return $null }
  if ($Value -is [System.Array]) {
    return @($Value | ForEach-Object { ConvertTo-PlainObject $_ })
  }
  if ($Value -is [System.Management.Automation.PSCustomObject]) {
    $hash = @{}
    foreach ($property in $Value.PSObject.Properties) {
      $hash[$property.Name] = ConvertTo-PlainObject $property.Value
    }
    return $hash
  }

  return $Value
}

function Get-ConfigValue {
  param(
    [Parameter(Mandatory = $true)]$Config,
    [Parameter(Mandatory = $true)][string]$Name,
    $Default = $null
  )

  if ($Config.PSObject.Properties.Name -contains $Name) {
    $value = $Config.$Name
    if ($null -ne $value -and $value -ne '') {
      return $value
    }
  }

  return $Default
}

function Resolve-SentinelPath {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) {
    return $null
  }

  return [Environment]::ExpandEnvironmentVariables($Path)
}

function Get-Sha256Text {
  param([Parameter(Mandatory = $true)][string]$Text)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
  }
}

function Get-HmacSha256Hex {
  param(
    [Parameter(Mandatory = $true)][string]$Text,
    [Parameter(Mandatory = $true)][string]$SharedSecret
  )

  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $key = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($SharedSecret))
  } finally {
    $sha.Dispose()
  }

  $hmac = [System.Security.Cryptography.HMACSHA256]::new($key)
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    return ([BitConverter]::ToString($hmac.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
  } finally {
    $hmac.Dispose()
  }
}

function Get-Sha256FileSafe {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [long]$MaxBytes
  )

  try {
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.Length -gt $MaxBytes) {
      return $null
    }

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
  } catch {
    return $null
  }
}

function Test-TermMatch {
  param(
    [string]$Text,
    [object[]]$Terms
  )

  if ($null -eq $Text) {
    $Text = ''
  }

  $lower = $Text.ToLowerInvariant()
  foreach ($term in @($Terms)) {
    $candidate = [string]$term
    if ($candidate -eq '') {
      continue
    }

    $candidateLower = $candidate.ToLowerInvariant()
    if ($candidateLower.Length -le 4) {
      $pattern = '(^|[^a-z0-9])' + [regex]::Escape($candidateLower) + '([^a-z0-9]|$)'
      if ([regex]::IsMatch($lower, $pattern)) {
        return $candidate
      }
      continue
    }

    if ($lower.Contains($candidateLower)) {
      return $candidate
    }
  }

  return $null
}

function ConvertTo-ReportPath {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

  $userProfile = [Environment]::GetFolderPath('UserProfile')
  if ($userProfile -and $Path.StartsWith($userProfile, [System.StringComparison]::OrdinalIgnoreCase)) {
    return $Path.Replace($userProfile, '%USERPROFILE%')
  }

  return $Path
}

function Get-MachineFingerprint {
  $machineGuid = ''
  try {
    $machineGuid = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
  } catch {
    $machineGuid = [Environment]::MachineName
  }

  return Get-Sha256Text ("sentinel:machine:{0}" -f $machineGuid)
}

function Get-LocalNetworkIdentity {
  $localIps = @()
  try {
    $localIps = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
      Where-Object { $_.IPAddress -notlike '127.*' -and $_.PrefixOrigin -ne 'WellKnown' } |
      Select-Object -ExpandProperty IPAddress -Unique
  } catch {
    try {
      $localIps = [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
        Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and $_.ToString() -notlike '127.*' } |
        ForEach-Object { $_.ToString() }
    } catch {
      $localIps = @()
    }
  }

  return @{
    hostName = [Environment]::MachineName
    localIps = @($localIps)
  }
}

function Invoke-SentinelJson {
  param(
    [Parameter(Mandatory = $true)][string]$Uri,
    [Parameter(Mandatory = $true)]$Body,
    [Parameter(Mandatory = $true)][string]$AgentKey
  )

  $headers = @{
    'Content-Type' = 'application/json'
    'X-Sentinel-Key' = $AgentKey
  }
  $json = $Body | ConvertTo-Json -Depth 30 -Compress
  $lastError = $null
  for ($attempt = 1; $attempt -le 2; $attempt++) {
    try {
      return Invoke-RestMethod -Uri $Uri -Method Post -Headers $headers -Body $json -TimeoutSec 60 -DisableKeepAlive
    } catch {
      $lastError = $_
      if ($attempt -lt 2) {
        Start-Sleep -Milliseconds 500
      }
    }
  }
  throw $lastError
}

function Send-SentinelSessionHeartbeat {
  param(
    [Parameter(Mandatory = $true)]$Config,
    [Parameter(Mandatory = $true)][string]$SessionId,
    [string]$DiscordId = '',
    [string]$Status = 'active',
    [scriptblock]$Log = $null
  )

  if ([string]::IsNullOrWhiteSpace($SessionId)) {
    return
  }

  try {
    Invoke-SentinelJson -Uri (($Config.cloudEndpoint.TrimEnd('/')) + '/v1/agent/heartbeat') -AgentKey $Config.agentKey -Body @{
      licenseKey = $Config.licenseKey
      sessionId = $SessionId
      discordId = $DiscordId
      status = $Status
    } | Out-Null
  } catch {
    if ($null -ne $Log) {
      & $Log ('Heartbeat sessione non riuscito: {0}' -f $_.Exception.Message)
    }
  }
}

function New-EncryptedEnvelope {
  param(
    [Parameter(Mandatory = $true)]$Payload,
    [Parameter(Mandatory = $true)][string]$SharedSecret
  )

  $payloadJson = $Payload | ConvertTo-Json -Depth 40 -Compress
  $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)
  $key = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($SharedSecret))
  $iv = New-Object byte[] 16
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)

  $aes = [System.Security.Cryptography.Aes]::Create()
  try {
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv
    $encryptor = $aes.CreateEncryptor()
    $cipherBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
  } finally {
    $aes.Dispose()
  }

  $hmacInput = New-Object byte[] ($iv.Length + $cipherBytes.Length)
  [Array]::Copy($iv, 0, $hmacInput, 0, $iv.Length)
  [Array]::Copy($cipherBytes, 0, $hmacInput, $iv.Length, $cipherBytes.Length)
  $hmac = [System.Security.Cryptography.HMACSHA256]::new($key)
  try {
    $tag = $hmac.ComputeHash($hmacInput)
  } finally {
    $hmac.Dispose()
  }

  return @{
    encrypted = $true
    alg = 'AES-256-CBC-HMAC-SHA256'
    iv = [Convert]::ToBase64String($iv)
    ciphertext = [Convert]::ToBase64String($cipherBytes)
    hmac = [Convert]::ToBase64String($tag)
  }
}

function Add-Finding {
  param(
    [System.Collections.Generic.List[object]]$Findings,
    [string]$Type,
    [string]$Severity,
    [string]$Signal,
    [string]$Reason,
    [string]$Path = $null,
    [string]$Sha256 = $null,
    [long]$Size = 0
  )

  $Findings.Add([pscustomobject]@{
    type = $Type
    severity = $Severity
    signal = $Signal
    reason = $Reason
    path = ConvertTo-ReportPath $Path
    sha256 = $Sha256
    size = $Size
  }) | Out-Null
}

function Get-ScanRoots {
  param($Config)

  $roots = @()
  $scanMode = [string](Get-ConfigValue -Config $Config -Name 'scanMode' -Default 'balanced')
  if ($scanMode -ne 'full') {
    foreach ($root in @((Get-ConfigValue -Config $Config -Name 'fastScanRoots' -Default @()))) {
      $resolved = Resolve-SentinelPath ([string]$root)
      if (-not [string]::IsNullOrWhiteSpace($resolved) -and (Test-Path -LiteralPath $resolved)) {
        $roots += (Resolve-Path -LiteralPath $resolved).Path
      }
    }
  }

  foreach ($root in @($Config.scanRoots)) {
    $resolved = Resolve-SentinelPath ([string]$root)
    if (-not [string]::IsNullOrWhiteSpace($resolved) -and (Test-Path -LiteralPath $resolved)) {
      $roots += (Resolve-Path -LiteralPath $resolved).Path
    }
  }

  if (($scanMode -eq 'full' -and $Config.includeFixedDrives -eq $true) -or @($roots).Count -eq 0) {
    $roots += Get-PSDrive -PSProvider FileSystem |
      Where-Object { $_.Root -match '^[A-Z]:\\$' } |
      Select-Object -ExpandProperty Root
  }

  return @($roots | Select-Object -Unique)
}

function Test-ExcludedPath {
  param(
    [string]$Path,
    [object[]]$ExcludedRoots
  )

  foreach ($root in @($ExcludedRoots)) {
    $text = [string]$root
    if ($text -ne '' -and $Path.StartsWith($text, [System.StringComparison]::OrdinalIgnoreCase)) {
      return $true
    }
  }

  return $false
}

function Resolve-SentinelPathList {
  param([object[]]$Values)

  $resolved = @()
  foreach ($value in @($Values)) {
    $path = Resolve-SentinelPath ([string]$value)
    if (-not [string]::IsNullOrWhiteSpace($path)) {
      $resolved += $path.TrimEnd('\')
    }
  }

  return @($resolved | Select-Object -Unique)
}

function Test-PathMatchesAny {
  param(
    [string]$Path,
    [object[]]$Patterns
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    return $false
  }

  $lower = $Path.ToLowerInvariant()
  foreach ($pattern in @($Patterns)) {
    $resolved = Resolve-SentinelPath ([string]$pattern)
    if ([string]::IsNullOrWhiteSpace($resolved)) {
      continue
    }

    $candidate = $resolved.TrimEnd('\').ToLowerInvariant()
    if ($candidate -and ($lower.StartsWith($candidate) -or $lower.Contains($candidate))) {
      return $true
    }
  }

  return $false
}

function Get-AuthenticodeSignatureSafe {
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
    return $null
  }

  try {
    return Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
  } catch {
    return $null
  }
}

function Test-TrustedPublisher {
  param(
    [string]$Path,
    $Signatures
  )

  $signature = Get-AuthenticodeSignatureSafe -Path $Path
  if ($null -eq $signature -or $signature.Status -ne 'Valid') {
    return $false
  }

  $subject = ''
  try {
    $subject = [string]$signature.SignerCertificate.Subject
  } catch {
    $subject = ''
  }

  foreach ($publisher in @((Get-ConfigValue -Config $Signatures -Name 'trustedPublishers' -Default @()))) {
    $candidate = [string]$publisher
    if ($candidate -and $subject.IndexOf($candidate, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
      return $true
    }
  }

  return $false
}

function Test-IgnoredRuntimeProcess {
  param(
    [string]$Name,
    [string]$Path,
    $Signatures
  )

  $rules = Get-ConfigValue -Config $Signatures -Name 'behaviorRules' -Default $null
  if ($null -eq $rules) {
    return $false
  }

  $text = ('{0} {1}' -f $Name, $Path).ToLowerInvariant()
  foreach ($ignored in @((Get-ConfigValue -Config $rules -Name 'ignoredProcessNames' -Default @()))) {
    $candidate = ([string]$ignored).ToLowerInvariant()
    if ($candidate -and $text.Contains($candidate)) {
      return $true
    }
  }

  return $false
}

function Update-SentinelSignatures {
  param(
    [Parameter(Mandatory = $true)]$Config,
    [Parameter(Mandatory = $true)]$CurrentSignatures,
    [scriptblock]$Log
  )

  if ([bool](Get-ConfigValue -Config $Config -Name 'signatureUpdateEnabled' -Default $true) -ne $true) {
    return $CurrentSignatures
  }

  try {
    & $Log '[progress:4] Aggiornamento firme anticheat...'
    $response = Invoke-SentinelJson -Uri (($Config.cloudEndpoint.TrimEnd('/')) + '/v1/signatures/latest') -AgentKey $Config.agentKey -Body @{
      licenseKey = $Config.licenseKey
      currentVersion = $CurrentSignatures.version
    }

    $dataRaw = [string]$response.dataRaw
    $expectedHmac = [string]$response.hmac
    if ([string]::IsNullOrWhiteSpace($dataRaw) -or [string]::IsNullOrWhiteSpace($expectedHmac)) {
      throw 'signature_feed_missing_hmac'
    }

    $actualHmac = Get-HmacSha256Hex -Text $dataRaw -SharedSecret $Config.sharedSecret
    if ($actualHmac -ne $expectedHmac.ToLowerInvariant()) {
      throw 'signature_feed_hmac_invalid'
    }

    $updated = $dataRaw | ConvertFrom-Json
    if ([string]$updated.version -ne [string]$CurrentSignatures.version) {
      $dataRaw | Set-Content -LiteralPath $Script:SignaturesPath -Encoding UTF8
      & $Log ('[progress:6] Firme aggiornate: {0}' -f $updated.version)
    } else {
      & $Log ('[progress:6] Firme gia aggiornate: {0}' -f $updated.version)
    }

    return $updated
  } catch {
    & $Log ('[progress:6] Aggiornamento firme non riuscito: {0}. Uso cache locale.' -f $_.Exception.Message)
    return $CurrentSignatures
  }
}

function Invoke-AgentBanPrecheck {
  param(
    [Parameter(Mandatory = $true)]$Config,
    [string]$DiscordId,
    [string]$DiscordTag,
    [string]$MachineFingerprint,
    $Network
  )

  if ([bool](Get-ConfigValue -Config $Config -Name 'banPrecheckEnabled' -Default $true) -ne $true) {
    return
  }

  $response = Invoke-SentinelJson -Uri (($Config.cloudEndpoint.TrimEnd('/')) + '/v1/agent/precheck') -AgentKey $Config.agentKey -Body @{
    licenseKey = $Config.licenseKey
    discordId = $DiscordId
    discordTag = $DiscordTag
    machineFingerprint = $MachineFingerprint
    localIps = @($Network.localIps)
  }

  $isBanned = [bool](Get-ConfigValue -Config $response -Name 'banned' -Default $false)
  $isAllowed = [bool](Get-ConfigValue -Config $response -Name 'allowed' -Default $true)
  if ($isBanned -eq $true -or $isAllowed -eq $false) {
    $message = [string]$response.message
    if ([string]::IsNullOrWhiteSpace($message)) {
      $message = ('Sentinel Anticheat: accesso bloccato. Motivo: {0}' -f $response.reason)
    }
    throw $message
  }
}

function Start-SentinelScan {
  param(
    [Parameter(Mandatory = $true)]$Config,
    [Parameter(Mandatory = $true)]$Signatures,
    [scriptblock]$Log,
    [string]$DiscordId = '',
    [string]$DiscordTag = ''
  )

  $Signatures = Update-SentinelSignatures -Config $Config -CurrentSignatures $Signatures -Log $Log

  & $Log '[progress:8] Preparazione identita locale...'
  $machineFingerprint = Get-MachineFingerprint
  $network = Get-LocalNetworkIdentity

  & $Log '[progress:10] Precheck ban cloud prima della scansione...'
  Invoke-AgentBanPrecheck -Config $Config -DiscordId $DiscordId -DiscordTag $DiscordTag -MachineFingerprint $machineFingerprint -Network $network

  & $Log '[progress:12] Apertura sessione cloud...'
  $session = Invoke-SentinelJson -Uri (($Config.cloudEndpoint.TrimEnd('/')) + '/v1/agent/connect') -AgentKey $Config.agentKey -Body @{
    licenseKey = $Config.licenseKey
    appVersion = $Config.version
    machineFingerprint = $machineFingerprint
    localIps = @($network.localIps)
    discordId = $DiscordId
    discordTag = $DiscordTag
  }

  $sessionBanned = [bool](Get-ConfigValue -Config $session -Name 'banned' -Default $false)
  $sessionAccepted = [bool](Get-ConfigValue -Config $session -Name 'accepted' -Default $true)
  if ($sessionBanned -eq $true -or $sessionAccepted -eq $false) {
    $message = [string]$session.message
    if ([string]::IsNullOrWhiteSpace($message)) {
      $message = ('Sentinel Anticheat: accesso bloccato. Motivo: {0}' -f $session.reason)
    }
    throw $message
  }

  $lastWorkerHeartbeat = Get-Date
  Send-SentinelSessionHeartbeat -Config $Config -SessionId ([string]$session.sessionId) -DiscordId $DiscordId -Status 'scanning' -Log $Log

  $findings = [System.Collections.Generic.List[object]]::new()
  $stats = [ordered]@{
    processes = 0
    services = 0
    drivers = 0
    filesVisited = 0
    filesHashed = 0
    fileErrors = 0
  }

  & $Log '[progress:18] Controllo processi attivi...'
  try {
    foreach ($process in Get-CimInstance Win32_Process -ErrorAction Stop) {
      $stats.processes++
      $name = [string]$process.Name
      $path = [string]$process.ExecutablePath
      $term = Test-TermMatch -Text ($name + ' ' + $path) -Terms $Signatures.suspiciousNames
      if ($term) {
        $hash = if ($path -and (Test-Path -LiteralPath $path)) { Get-Sha256FileSafe -Path $path -MaxBytes $Config.maxFileBytesToHash } else { $null }
        Add-Finding -Findings $findings -Type 'process' -Severity 'high' -Signal $term -Reason 'Suspicious process name or path' -Path $path -Sha256 $hash
      }
    }
  } catch {
    Add-Finding -Findings $findings -Type 'scan_error' -Severity 'low' -Signal 'process_scan' -Reason $_.Exception.Message
  }

  & $Log '[progress:34] Controllo servizi e driver...'
  try {
    foreach ($service in Get-CimInstance Win32_Service -ErrorAction Stop) {
      $stats.services++
      $text = ('{0} {1} {2}' -f $service.Name, $service.DisplayName, $service.PathName)
      $term = Test-TermMatch -Text $text -Terms $Signatures.suspiciousNames
      if ($term) {
        Add-Finding -Findings $findings -Type 'service' -Severity 'medium' -Signal $term -Reason 'Suspicious service metadata' -Path ([string]$service.PathName)
      }
    }

    foreach ($driver in Get-CimInstance Win32_SystemDriver -ErrorAction Stop) {
      $stats.drivers++
      $text = ('{0} {1} {2}' -f $driver.Name, $driver.DisplayName, $driver.PathName)
      $driverTerm = Test-TermMatch -Text $text -Terms $Signatures.suspiciousDrivers
      if (-not $driverTerm) {
        $driverTerm = Test-TermMatch -Text $text -Terms $Signatures.suspiciousNames
      }

      if ($driverTerm) {
        Add-Finding -Findings $findings -Type 'driver' -Severity 'high' -Signal $driverTerm -Reason 'Suspicious driver metadata' -Path ([string]$driver.PathName)
      }
    }
  } catch {
    Add-Finding -Findings $findings -Type 'scan_error' -Severity 'low' -Signal 'service_driver_scan' -Reason $_.Exception.Message
  }

  $roots = Get-ScanRoots -Config $Config
  & $Log ('[progress:48] Scansione file su: {0}' -f ($roots -join ', '))
  $scanStarted = Get-Date
  $maxScanSeconds = [int](Get-ConfigValue -Config $Config -Name 'maxScanSeconds' -Default 120)
  $timeLimitReached = $false

  foreach ($root in $roots) {
    if ($timeLimitReached) {
      break
    }

    if (Test-ExcludedPath -Path $root -ExcludedRoots $Config.excludedRoots) {
      continue
    }

    try {
      foreach ($item in Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue) {
        $stats.filesVisited++

        if (($stats.filesVisited % 350) -eq 0) {
          $elapsed = [Math]::Max(1, [int]((Get-Date) - $scanStarted).TotalSeconds)
          $percent = [Math]::Min(86, 48 + [int](([Math]::Min($elapsed, $maxScanSeconds) / [Math]::Max($maxScanSeconds, 1)) * 38))
          & $Log ('[progress:{0}] Scansione file... {1} file controllati, {2} hash calcolati' -f $percent, $stats.filesVisited, $stats.filesHashed)

          if (((Get-Date) - $lastWorkerHeartbeat).TotalSeconds -ge 10) {
            Send-SentinelSessionHeartbeat -Config $Config -SessionId ([string]$session.sessionId) -DiscordId $DiscordId -Status 'scanning' -Log $Log
            $lastWorkerHeartbeat = Get-Date
          }
        }

        if ([int]((Get-Date) - $scanStarted).TotalSeconds -ge $maxScanSeconds) {
          $timeLimitReached = $true
          & $Log ('[progress:87] Limite tempo scansione raggiunto: {0}s, passo alla chiusura report.' -f $maxScanSeconds)
          break
        }

        if (($findings.Count -ge $Config.maxFindings)) {
          break
        }

        if (Test-ExcludedPath -Path $item.FullName -ExcludedRoots $Config.excludedRoots) {
          continue
        }

        $extension = $item.Extension.ToLowerInvariant()
        $pathText = $item.FullName
        $nameTerm = Test-TermMatch -Text $pathText -Terms $Signatures.suspiciousNames
        $pathTerm = Test-TermMatch -Text $pathText -Terms $Signatures.suspiciousPaths
        $shouldHash = @($Config.suspectExtensions) -contains $extension
        $hash = $null

        if ($shouldHash -or $nameTerm) {
          $hash = Get-Sha256FileSafe -Path $item.FullName -MaxBytes $Config.maxFileBytesToHash
          if ($hash) { $stats.filesHashed++ }
        }

        if ($hash -and (@($Signatures.knownBadSha256) -contains $hash)) {
          Add-Finding -Findings $findings -Type 'file' -Severity 'critical' -Signal $hash -Reason 'Known bad SHA-256' -Path $item.FullName -Sha256 $hash -Size $item.Length
          continue
        }

        if ($nameTerm) {
          Add-Finding -Findings $findings -Type 'file' -Severity 'high' -Signal $nameTerm -Reason 'Suspicious file name or path' -Path $item.FullName -Sha256 $hash -Size $item.Length
          continue
        }

        if ($pathTerm -and $shouldHash) {
          continue
        }
      }
    } catch {
      $stats.fileErrors++
      Add-Finding -Findings $findings -Type 'scan_error' -Severity 'low' -Signal $root -Reason $_.Exception.Message
    }
  }

  $highest = 'clean'
  if ($findings | Where-Object { $_.severity -eq 'critical' }) { $highest = 'critical' }
  elseif ($findings | Where-Object { $_.severity -eq 'high' }) { $highest = 'high' }
  elseif ($findings | Where-Object { $_.severity -eq 'medium' }) { $highest = 'medium' }
  elseif ($findings.Count -gt 0) { $highest = 'low' }

  $report = [ordered]@{
    reportId = [guid]::NewGuid().ToString()
    generatedAt = (Get-Date).ToUniversalTime().ToString('o')
    app = @{
      name = $Config.appName
      version = $Config.version
      scanMode = $Config.scanMode
      signatureVersion = $Signatures.version
    }
    identity = @{
      machineFingerprint = $machineFingerprint
      userFingerprint = Get-Sha256Text ("sentinel:user:{0}" -f [Environment]::UserName)
      publicIp = $session.publicIp
      localIps = $network.localIps
      hostNameHash = Get-Sha256Text ("sentinel:host:{0}" -f $network.hostName)
      discord = @{
        id = $DiscordId
        username = $DiscordTag
      }
    }
    summary = @{
      highestSeverity = $highest
      findingCount = $findings.Count
      suspicious = $findings.Count -gt 0
      stats = $stats
    }
    findings = @($findings)
  }

  $reportPath = Join-Path $Script:ReportsPath ('{0}.json' -f $report.reportId)
  $report | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $reportPath -Encoding UTF8
  & $Log ('[progress:90] Report locale scritto: {0}' -f $reportPath)
  Send-SentinelSessionHeartbeat -Config $Config -SessionId ([string]$session.sessionId) -DiscordId $DiscordId -Status 'active' -Log $Log

  if (($Config.reportOnlyWhenSuspicious -eq $true) -and ($findings.Count -eq 0)) {
    & $Log '[progress:100] Nessun sospetto trovato: upload report saltato per configurazione.'
    return @{ report = $report; upload = $null; session = $session }
  }

  & $Log '[progress:94] Cifratura report e upload al cloud...'
  $envelope = New-EncryptedEnvelope -Payload $report -SharedSecret $Config.sharedSecret
  $upload = Invoke-SentinelJson -Uri (($Config.cloudEndpoint.TrimEnd('/')) + '/v1/agent/report') -AgentKey $Config.agentKey -Body @{
    licenseKey = $Config.licenseKey
    sessionId = $session.sessionId
    discordId = $DiscordId
    discordTag = $DiscordTag
    machineFingerprint = $machineFingerprint
    envelope = $envelope
  }

  & $Log '[progress:100] Upload completato.'
  return @{ report = $report; upload = $upload; session = $session }
}

$config = Read-JsonFile $Script:ConfigPath
$signatures = Read-JsonFile $Script:SignaturesPath
New-Item -ItemType Directory -Force -Path $Script:LogsPath, $Script:ReportsPath | Out-Null

if ($WorkerScan) {
  try {
    if ([string]::IsNullOrWhiteSpace($WorkerProgressPath) -or [string]::IsNullOrWhiteSpace($WorkerResultPath) -or [string]::IsNullOrWhiteSpace($WorkerErrorPath)) {
      throw 'Worker paths are required.'
    }

    '' | Set-Content -LiteralPath $WorkerProgressPath -Encoding UTF8
    $result = Start-SentinelScan -Config $config -Signatures $signatures -Log {
      param($message)
      Add-Content -LiteralPath $WorkerProgressPath -Value ('[{0}] {1}' -f (Get-Date).ToString('HH:mm:ss'), $message) -Encoding UTF8
    } -DiscordId $WorkerDiscordId -DiscordTag $WorkerDiscordTag

    $report = $result['report']
    $upload = $result['upload']
    $session = $result['session']
    @{
      ok = $true
      findingCount = $report.summary.findingCount
      highestSeverity = $report.summary.highestSeverity
      reportId = $report.reportId
      uploadReportId = if ($upload) { $upload.reportId } else { $null }
      action = if ($upload) { $upload.action } else { 'allow' }
      sessionId = if ($session) { $session.sessionId } else { $null }
      publicIp = if ($session) { $session.publicIp } else { $null }
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $WorkerResultPath -Encoding UTF8
    exit 0
  } catch {
    @{
      ok = $false
      message = $_.Exception.Message
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $WorkerErrorPath -Encoding UTF8
    exit 1
  }
}

function New-SentinelLogoBitmap {
  $bitmap = New-Object System.Drawing.Bitmap(112, 112)
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $graphics.Clear([System.Drawing.Color]::Transparent)

  $rect = New-Object System.Drawing.Rectangle(10, 8, 92, 96)
  $path = New-Object System.Drawing.Drawing2D.GraphicsPath
  $points = @(
    (New-Object System.Drawing.Point(56, 8)),
    (New-Object System.Drawing.Point(98, 25)),
    (New-Object System.Drawing.Point(91, 75)),
    (New-Object System.Drawing.Point(56, 104)),
    (New-Object System.Drawing.Point(21, 75)),
    (New-Object System.Drawing.Point(14, 25))
  )
  $path.AddPolygon([System.Drawing.Point[]]$points)

  $shadowPath = $path.Clone()
  $matrix = New-Object System.Drawing.Drawing2D.Matrix
  $matrix.Translate(0, 4)
  $shadowPath.Transform($matrix)
  $shadowBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(80, 0, 0, 0))
  $graphics.FillPath($shadowBrush, $shadowPath)

  $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, [System.Drawing.Color]::FromArgb(51, 219, 135), [System.Drawing.Color]::FromArgb(18, 91, 75), 35)
  $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(212, 255, 231), 3)
  $graphics.FillPath($brush, $path)
  $graphics.DrawPath($pen, $path)

  $ringPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(235, 245, 255), 4)
  $scanPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(10, 23, 31), 4)
  $graphics.DrawArc($ringPen, 31, 32, 50, 50, 205, 280)
  $graphics.DrawLine($scanPen, 56, 24, 56, 36)
  $graphics.DrawLine($scanPen, 56, 78, 56, 91)
  $graphics.DrawLine($scanPen, 24, 56, 37, 56)
  $graphics.DrawLine($scanPen, 75, 56, 89, 56)
  $centerBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(245, 255, 250))
  $graphics.FillEllipse($centerBrush, 47, 47, 18, 18)

  $centerBrush.Dispose()
  $scanPen.Dispose()
  $ringPen.Dispose()
  $pen.Dispose()
  $brush.Dispose()
  $shadowBrush.Dispose()
  $matrix.Dispose()
  $shadowPath.Dispose()
  $path.Dispose()
  $graphics.Dispose()
  return $bitmap
}

function New-UiFont {
  param(
    [string[]]$Names,
    [float]$Size,
    [System.Drawing.FontStyle]$Style = [System.Drawing.FontStyle]::Regular
  )

  foreach ($name in $Names) {
    try {
      $font = New-Object System.Drawing.Font($name, $Size, $Style)
      if ($font -and $font.FontFamily -and ($font.FontFamily.Name -ieq $name -or $font.Name -ieq $name)) {
        return $font
      }
      if ($font) { $font.Dispose() }
    } catch {}
  }

  return New-Object System.Drawing.Font('Bahnschrift', $Size, $Style)
}

function New-RoundedRectanglePath {
  param(
    [System.Drawing.Rectangle]$Rectangle,
    [int]$Radius
  )

  $diameter = [Math]::Max(2, $Radius * 2)
  $path = New-Object System.Drawing.Drawing2D.GraphicsPath
  $path.AddArc($Rectangle.X, $Rectangle.Y, $diameter, $diameter, 180, 90)
  $path.AddArc(($Rectangle.Right - $diameter), $Rectangle.Y, $diameter, $diameter, 270, 90)
  $path.AddArc(($Rectangle.Right - $diameter), ($Rectangle.Bottom - $diameter), $diameter, $diameter, 0, 90)
  $path.AddArc($Rectangle.X, ($Rectangle.Bottom - $diameter), $diameter, $diameter, 90, 90)
  $path.CloseFigure()
  return $path
}

function Set-RoundedControlRegion {
  param(
    [System.Windows.Forms.Control]$Control,
    [int]$Radius
  )

  if ($Control.Width -le 0 -or $Control.Height -le 0) {
    return
  }

  $rect = New-Object System.Drawing.Rectangle(0, 0, ($Control.Width - 1), ($Control.Height - 1))
  $path = New-RoundedRectanglePath -Rectangle $rect -Radius $Radius
  $Control.Region = New-Object System.Drawing.Region($path)
  $path.Dispose()
}

function New-SentinelPanel {
  param(
    [int]$X,
    [int]$Y,
    [int]$Width,
    [int]$Height,
    [int]$Radius = 18,
    [System.Drawing.Color]$StartColor = ([System.Drawing.Color]::FromArgb(236, 5, 12, 20)),
    [System.Drawing.Color]$EndColor = ([System.Drawing.Color]::FromArgb(236, 8, 24, 39)),
    [System.Drawing.Color]$BorderColor = ([System.Drawing.Color]::FromArgb(96, 83, 132, 172)),
    [System.Drawing.Color]$AccentColor = ([System.Drawing.Color]::FromArgb(0, 148, 255)),
    [string]$Accent = 'none'
  )

  $panel = New-Object System.Windows.Forms.Panel
  $panel.Location = New-Object System.Drawing.Point($X, $Y)
  $panel.Size = New-Object System.Drawing.Size($Width, $Height)
  $panel.BackColor = [System.Drawing.Color]::Transparent
  $panel.Tag = @{
    Radius = $Radius
    StartColor = $StartColor
    EndColor = $EndColor
    BorderColor = $BorderColor
    AccentColor = $AccentColor
    Accent = $Accent
  }
  $panel.Add_Paint({
    param($sender, $event)

    $style = $sender.Tag
    $g = $event.Graphics
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $rect = New-Object System.Drawing.Rectangle(0, 0, ($sender.Width - 1), ($sender.Height - 1))
    $path = New-RoundedRectanglePath -Rectangle $rect -Radius ([int]$style.Radius)
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $style.StartColor, $style.EndColor, 35)
    $border = New-Object System.Drawing.Pen($style.BorderColor, 1)

    $g.FillPath($brush, $path)
    $g.DrawPath($border, $path)

    if ($style.Accent -eq 'bottom') {
      $accentPen = New-Object System.Drawing.Pen($style.AccentColor, 2)
      $g.DrawLine($accentPen, 24, ($sender.Height - 9), ($sender.Width - 24), ($sender.Height - 9))
      $accentPen.Dispose()
    } elseif ($style.Accent -eq 'left') {
      $accentPen = New-Object System.Drawing.Pen($style.AccentColor, 3)
      $g.DrawLine($accentPen, 0, 18, 0, ($sender.Height - 18))
      $accentPen.Dispose()
    }

    $border.Dispose()
    $brush.Dispose()
    $path.Dispose()
  })
  Set-RoundedControlRegion -Control $panel -Radius $Radius
  return $panel
}

function New-UiLabel {
  param(
    [string]$Text,
    [int]$X,
    [int]$Y,
    [int]$Width,
    [int]$Height,
    [float]$Size,
    [System.Drawing.Color]$Color,
    [string[]]$Names = @('Segoe UI Variable Text', 'Segoe UI', 'Bahnschrift'),
    [System.Drawing.FontStyle]$Style = [System.Drawing.FontStyle]::Regular,
    [string]$Align = 'MiddleLeft'
  )

  $label = New-Object System.Windows.Forms.Label
  $label.Text = $Text
  $label.Location = New-Object System.Drawing.Point($X, $Y)
  $label.Size = New-Object System.Drawing.Size($Width, $Height)
  $label.Font = New-UiFont -Names $Names -Size $Size -Style $Style
  $label.ForeColor = $Color
  $label.BackColor = [System.Drawing.Color]::Transparent
  $label.TextAlign = $Align
  return $label
}

function New-StatusTile {
  param(
    [string]$Title,
    [string]$Value,
    [string]$Detail,
    [int]$X,
    [int]$Y
  )

  $tile = New-SentinelPanel -X $X -Y $Y -Width 334 -Height 92 -Radius 18 `
    -StartColor ([System.Drawing.Color]::FromArgb(230, 5, 15, 25)) `
    -EndColor ([System.Drawing.Color]::FromArgb(230, 9, 29, 46)) `
    -BorderColor ([System.Drawing.Color]::FromArgb(110, 37, 91, 133)) `
    -AccentColor ([System.Drawing.Color]::FromArgb(0, 148, 255)) `
    -Accent 'left'

  $tile.Controls.Add((New-UiLabel -Text $Title -X 24 -Y 14 -Width 260 -Height 18 -Size 8.5 `
    -Color ([System.Drawing.Color]::FromArgb(125, 181, 224)) `
    -Names @('Bahnschrift', 'Segoe UI Variable Text', 'Segoe UI') `
    -Style ([System.Drawing.FontStyle]::Bold)))

  $valueLabel = New-UiLabel -Text $Value -X 24 -Y 34 -Width 285 -Height 26 -Size 12 `
    -Color ([System.Drawing.Color]::FromArgb(238, 245, 252)) `
    -Names @('Segoe UI Variable Display', 'Bahnschrift', 'Segoe UI') `
    -Style ([System.Drawing.FontStyle]::Bold)
  $tile.Controls.Add($valueLabel)

  $tile.Controls.Add((New-UiLabel -Text $Detail -X 24 -Y 63 -Width 285 -Height 18 -Size 8.5 `
    -Color ([System.Drawing.Color]::FromArgb(145, 162, 180)) `
    -Names @('Segoe UI Variable Text', 'Segoe UI', 'Bahnschrift')))

  $form.Controls.Add($tile)
  return $valueLabel
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Sentinel Anticheat'
if (Test-Path -LiteralPath $Script:IconPath) {
  $form.Icon = New-Object System.Drawing.Icon($Script:IconPath)
}
$form.ClientSize = New-Object System.Drawing.Size(1120, 820)
$form.MinimumSize = New-Object System.Drawing.Size(1120, 820)
$form.StartPosition = 'CenterScreen'
$form.BackColor = [System.Drawing.Color]::FromArgb(2, 7, 12)
$form.ForeColor = [System.Drawing.Color]::White
$form.Font = New-UiFont -Names @('Segoe UI Variable Text', 'Segoe UI', 'Bahnschrift') -Size 10
$form.Add_Paint({
  param($sender, $event)

  $g = $event.Graphics
  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $rect = $sender.ClientRectangle
  $background = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    $rect,
    [System.Drawing.Color]::FromArgb(1, 6, 11),
    [System.Drawing.Color]::FromArgb(5, 18, 31),
    90
  )
  $g.FillRectangle($background, $rect)
  $background.Dispose()

  $gridPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(18, 43, 94, 136), 1)
  for ($x = 0; $x -lt $rect.Width; $x += 64) {
    $g.DrawLine($gridPen, $x, 0, $x, $rect.Height)
  }
  for ($y = 32; $y -lt $rect.Height; $y += 64) {
    $g.DrawLine($gridPen, 0, $y, $rect.Width, $y)
  }
  $gridPen.Dispose()

  $diagonalPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(28, 0, 148, 255), 1)
  for ($x = -$rect.Height; $x -lt $rect.Width; $x += 96) {
    $g.DrawLine($diagonalPen, $x, $rect.Height, ($x + $rect.Height), 0)
  }
  $diagonalPen.Dispose()

  $topPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(155, 0, 148, 255), 2)
  $g.DrawLine($topPen, 0, 0, $rect.Width, 0)
  $topPen.Dispose()
})

$topBar = New-Object System.Windows.Forms.Panel
$topBar.Location = New-Object System.Drawing.Point(0, 0)
$topBar.Size = New-Object System.Drawing.Size(1120, 78)
$topBar.BackColor = [System.Drawing.Color]::Transparent
$topBar.Add_Paint({
  param($sender, $event)
  $g = $event.Graphics
  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $rect = $sender.ClientRectangle
  $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    $rect,
    [System.Drawing.Color]::FromArgb(235, 2, 8, 14),
    [System.Drawing.Color]::FromArgb(210, 6, 20, 34),
    0
  )
  $g.FillRectangle($brush, $rect)
  $brush.Dispose()
  $linePen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(90, 29, 105, 160), 1)
  $g.DrawLine($linePen, 0, ($rect.Height - 1), $rect.Width, ($rect.Height - 1))
  $linePen.Dispose()
})
$form.Controls.Add($topBar)

$topLogo = New-Object System.Windows.Forms.PictureBox
if (Test-Path -LiteralPath $Script:LogoPath) {
  $topLogo.Image = [System.Drawing.Image]::FromFile($Script:LogoPath)
} else {
  $topLogo.Image = New-SentinelLogoBitmap
}
$topLogo.Location = New-Object System.Drawing.Point(30, 15)
$topLogo.Size = New-Object System.Drawing.Size(48, 48)
$topLogo.SizeMode = 'Zoom'
$topLogo.BackColor = [System.Drawing.Color]::Transparent
$topBar.Controls.Add($topLogo)

$topBar.Controls.Add((New-UiLabel -Text 'Sentinel Anticheat' -X 92 -Y 16 -Width 280 -Height 26 -Size 12.5 `
  -Color ([System.Drawing.Color]::FromArgb(239, 246, 252)) `
  -Names @('Segoe UI Variable Display', 'Bahnschrift', 'Segoe UI') `
  -Style ([System.Drawing.FontStyle]::Bold)))

$topBar.Controls.Add((New-UiLabel -Text 'FIVEM DESKTOP PROTECTION' -X 94 -Y 43 -Width 280 -Height 18 -Size 8.2 `
  -Color ([System.Drawing.Color]::FromArgb(145, 162, 180)) `
  -Names @('Bahnschrift', 'Segoe UI Variable Text', 'Segoe UI') `
  -Style ([System.Drawing.FontStyle]::Bold)))

$versionBadge = New-UiLabel -Text ('v{0}  LIVE GUARD' -f $config.version) -X 930 -Y 22 -Width 150 -Height 34 -Size 8.5 `
  -Color ([System.Drawing.Color]::FromArgb(208, 230, 246)) `
  -Names @('Bahnschrift', 'Segoe UI') `
  -Style ([System.Drawing.FontStyle]::Bold) `
  -Align 'MiddleCenter'
$versionBadge.BackColor = [System.Drawing.Color]::FromArgb(16, 39, 60)
$topBar.Controls.Add($versionBadge)
Set-RoundedControlRegion -Control $versionBadge -Radius 12

$hero = New-SentinelPanel -X 36 -Y 102 -Width 1048 -Height 294 -Radius 28 `
  -StartColor ([System.Drawing.Color]::FromArgb(232, 3, 10, 17)) `
  -EndColor ([System.Drawing.Color]::FromArgb(232, 8, 27, 45)) `
  -BorderColor ([System.Drawing.Color]::FromArgb(120, 34, 100, 154)) `
  -AccentColor ([System.Drawing.Color]::FromArgb(0, 148, 255)) `
  -Accent 'bottom'
$form.Controls.Add($hero)

$logoFrame = New-Object System.Windows.Forms.Panel
$logoFrame.Location = New-Object System.Drawing.Point(34, 28)
$logoFrame.Size = New-Object System.Drawing.Size(238, 238)
$logoFrame.BackColor = [System.Drawing.Color]::Transparent
$logoFrame.Add_Paint({
  param($sender, $event)
  $g = $event.Graphics
  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $rect = New-Object System.Drawing.Rectangle(0, 0, ($sender.Width - 1), ($sender.Height - 1))
  $path = New-RoundedRectanglePath -Rectangle $rect -Radius 24
  $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    $rect,
    [System.Drawing.Color]::FromArgb(246, 4, 10, 17),
    [System.Drawing.Color]::FromArgb(238, 12, 28, 44),
    45
  )
  $g.FillPath($brush, $path)
  $border = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(125, 91, 132, 164), 1)
  $accent = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(170, 0, 148, 255), 2)
  $g.DrawPath($border, $path)
  $g.DrawLine($accent, 44, ($sender.Height - 9), ($sender.Width - 44), ($sender.Height - 9))
  $accent.Dispose()
  $border.Dispose()
  $brush.Dispose()
  $path.Dispose()
})
$hero.Controls.Add($logoFrame)
Set-RoundedControlRegion -Control $logoFrame -Radius 24

$logo = New-Object System.Windows.Forms.PictureBox
if (Test-Path -LiteralPath $Script:LogoPath) {
  $logo.Image = [System.Drawing.Image]::FromFile($Script:LogoPath)
} else {
  $logo.Image = New-SentinelLogoBitmap
}
$logo.Location = New-Object System.Drawing.Point(24, 24)
$logo.Size = New-Object System.Drawing.Size(190, 190)
$logo.SizeMode = 'Zoom'
$logo.BackColor = [System.Drawing.Color]::Transparent
$logoFrame.Controls.Add($logo)
Set-RoundedControlRegion -Control $logo -Radius 18

$title = New-Object System.Windows.Forms.Label
$title.Text = 'SENTINEL'
$title.Font = New-UiFont -Names @('Segoe UI Variable Display', 'Bahnschrift', 'Segoe UI') -Size 42 -Style ([System.Drawing.FontStyle]::Bold)
$title.Location = New-Object System.Drawing.Point(314, 42)
$title.Size = New-Object System.Drawing.Size(420, 58)
$title.TextAlign = 'MiddleLeft'
$title.ForeColor = [System.Drawing.Color]::FromArgb(238, 244, 250)
$title.BackColor = [System.Drawing.Color]::Transparent
$hero.Controls.Add($title)

$product = New-Object System.Windows.Forms.Label
$product.Text = 'ANTICHEAT'
$product.Font = New-UiFont -Names @('Bahnschrift', 'Segoe UI Variable Display', 'Segoe UI') -Size 19
$product.Location = New-Object System.Drawing.Point(318, 104)
$product.Size = New-Object System.Drawing.Size(300, 34)
$product.ForeColor = [System.Drawing.Color]::FromArgb(0, 149, 255)
$product.BackColor = [System.Drawing.Color]::Transparent
$hero.Controls.Add($product)

$accentLine = New-Object System.Windows.Forms.Panel
$accentLine.Location = New-Object System.Drawing.Point(318, 144)
$accentLine.Size = New-Object System.Drawing.Size(238, 2)
$accentLine.BackColor = [System.Drawing.Color]::FromArgb(0, 126, 214)
$hero.Controls.Add($accentLine)

$subtitle = New-Object System.Windows.Forms.Label
$subtitle.Text = 'Protezione desktop per FiveM con verifica locale, identita Discord, sessione live e runtime monitor.'
$subtitle.Font = New-UiFont -Names @('Segoe UI Variable Text', 'Segoe UI', 'Bahnschrift') -Size 10.5
$subtitle.Location = New-Object System.Drawing.Point(318, 166)
$subtitle.Size = New-Object System.Drawing.Size(520, 42)
$subtitle.TextAlign = 'TopLeft'
$subtitle.ForeColor = [System.Drawing.Color]::FromArgb(178, 197, 214)
$subtitle.BackColor = [System.Drawing.Color]::Transparent
$hero.Controls.Add($subtitle)

$discordLogin = New-Object System.Windows.Forms.Button
$discordLogin.Text = 'Accedi con Discord'
$discordLogin.Font = New-UiFont -Names @('Segoe UI Variable Text', 'Bahnschrift', 'Segoe UI') -Size 9.5 -Style ([System.Drawing.FontStyle]::Bold)
$discordLogin.Location = New-Object System.Drawing.Point(318, 228)
$discordLogin.Size = New-Object System.Drawing.Size(180, 42)
$discordLogin.BackColor = [System.Drawing.Color]::FromArgb(7, 22, 38)
$discordLogin.ForeColor = [System.Drawing.Color]::White
$discordLogin.FlatStyle = 'Flat'
$discordLogin.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(0, 132, 220)
$discordLogin.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(12, 35, 55)
$discordLogin.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(6, 70, 114)
$discordLogin.Cursor = [System.Windows.Forms.Cursors]::Hand
$hero.Controls.Add($discordLogin)
Set-RoundedControlRegion -Control $discordLogin -Radius 12

$discordStatus = New-Object System.Windows.Forms.Label
$discordStatus.Text = 'Discord non collegato'
$discordStatus.Font = New-UiFont -Names @('Segoe UI Variable Text', 'Segoe UI', 'Bahnschrift') -Size 9
$discordStatus.Location = New-Object System.Drawing.Point(516, 235)
$discordStatus.Size = New-Object System.Drawing.Size(250, 28)
$discordStatus.ForeColor = [System.Drawing.Color]::FromArgb(157, 171, 187)
$discordStatus.TextAlign = 'MiddleLeft'
$discordStatus.BackColor = [System.Drawing.Color]::Transparent
$hero.Controls.Add($discordStatus)

$connect = New-Object System.Windows.Forms.Button
$connect.Text = 'Connetti'
$connect.Font = New-UiFont -Names @('Segoe UI Variable Text', 'Bahnschrift', 'Segoe UI') -Size 13 -Style ([System.Drawing.FontStyle]::Bold)
$connect.Location = New-Object System.Drawing.Point(812, 190)
$connect.Size = New-Object System.Drawing.Size(190, 60)
$connect.BackColor = [System.Drawing.Color]::FromArgb(44, 65, 84)
$connect.ForeColor = [System.Drawing.Color]::White
$connect.FlatStyle = 'Flat'
$connect.FlatAppearance.BorderSize = 0
$connect.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(0, 138, 229)
$connect.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(0, 90, 155)
$connect.Cursor = [System.Windows.Forms.Cursors]::Hand
$connect.Enabled = $true
$hero.Controls.Add($connect)
Set-RoundedControlRegion -Control $connect -Radius 18

$hero.Controls.Add((New-UiLabel -Text 'READY CHECK' -X 812 -Y 150 -Width 190 -Height 24 -Size 8.5 `
  -Color ([System.Drawing.Color]::FromArgb(125, 181, 224)) `
  -Names @('Bahnschrift', 'Segoe UI') `
  -Style ([System.Drawing.FontStyle]::Bold) `
  -Align 'MiddleCenter'))

$discordTileValue = New-StatusTile -Title 'DISCORD LINK' -Value 'NON COLLEGATO' -Detail 'Identita richiesta prima della sessione' -X 36 -Y 418
$sessionTileValue = New-StatusTile -Title 'LIVE SESSION' -Value 'IN ATTESA' -Detail 'Heartbeat desktop verso il server' -X 393 -Y 418
$runtimeTileValue = New-StatusTile -Title 'RUNTIME GUARD' -Value 'STANDBY' -Detail 'Monitor processi e moduli sensibili' -X 750 -Y 418

$consent = New-Object System.Windows.Forms.CheckBox
$consent.Text = 'Autorizzo la verifica locale e l''invio cifrato del report.'
$consent.Location = New-Object System.Drawing.Point(50, 530)
$consent.Size = New-Object System.Drawing.Size(610, 28)
$consent.Checked = $true
$consent.ForeColor = [System.Drawing.Color]::FromArgb(218, 229, 239)
$consent.BackColor = [System.Drawing.Color]::Transparent
$consent.Font = New-UiFont -Names @('Segoe UI Variable Text', 'Segoe UI', 'Bahnschrift') -Size 9.3
$form.Controls.Add($consent)

$scanPanel = New-SentinelPanel -X 36 -Y 570 -Width 1048 -Height 84 -Radius 20 `
  -StartColor ([System.Drawing.Color]::FromArgb(225, 3, 10, 17)) `
  -EndColor ([System.Drawing.Color]::FromArgb(225, 7, 22, 36)) `
  -BorderColor ([System.Drawing.Color]::FromArgb(92, 44, 101, 146))
$form.Controls.Add($scanPanel)

$status = New-Object System.Windows.Forms.Label
$status.Text = 'Pronto'
$status.Location = New-Object System.Drawing.Point(24, 16)
$status.Size = New-Object System.Drawing.Size(820, 24)
$status.TextAlign = 'MiddleLeft'
$status.ForeColor = [System.Drawing.Color]::FromArgb(229, 237, 246)
$status.BackColor = [System.Drawing.Color]::Transparent
$status.Font = New-UiFont -Names @('Segoe UI Variable Text', 'Segoe UI', 'Bahnschrift') -Size 9.5 -Style ([System.Drawing.FontStyle]::Bold)
$scanPanel.Controls.Add($status)

$progressPercentLabel = New-UiLabel -Text '0%' -X 928 -Y 16 -Width 82 -Height 24 -Size 9.5 `
  -Color ([System.Drawing.Color]::FromArgb(130, 190, 232)) `
  -Names @('Bahnschrift', 'Segoe UI') `
  -Style ([System.Drawing.FontStyle]::Bold) `
  -Align 'MiddleRight'
$scanPanel.Controls.Add($progressPercentLabel)

$Script:ProgressValue = 0
$progress = New-Object System.Windows.Forms.Panel
$progress.Location = New-Object System.Drawing.Point(24, 50)
$progress.Size = New-Object System.Drawing.Size(1000, 18)
$progress.BackColor = [System.Drawing.Color]::Transparent
$progress.Add_Paint({
  param($sender, $event)

  $g = $event.Graphics
  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $rect = New-Object System.Drawing.Rectangle(0, 0, ($sender.Width - 1), ($sender.Height - 1))
  $track = New-RoundedRectanglePath -Rectangle $rect -Radius 9
  $trackBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    $rect,
    [System.Drawing.Color]::FromArgb(245, 5, 10, 17),
    [System.Drawing.Color]::FromArgb(245, 13, 27, 42),
    90
  )
  $g.FillPath($trackBrush, $track)

  $value = [Math]::Max(0, [Math]::Min(100, [int]$Script:ProgressValue))
  if ($value -gt 0) {
    $fillWidth = [Math]::Max(18, [int](($sender.Width - 1) * ($value / 100)))
    $fillRect = New-Object System.Drawing.Rectangle(0, 0, $fillWidth, ($sender.Height - 1))
    $fillPath = New-RoundedRectanglePath -Rectangle $fillRect -Radius 9
    $fillBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
      $fillRect,
      [System.Drawing.Color]::FromArgb(26, 176, 255),
      [System.Drawing.Color]::FromArgb(0, 103, 188),
      0
    )
    $g.FillPath($fillBrush, $fillPath)
    $shinePen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(110, 220, 244, 255), 1)
    $g.DrawLine($shinePen, 12, 4, ([Math]::Max(12, $fillWidth - 14)), 4)
    $shinePen.Dispose()
    $fillBrush.Dispose()
    $fillPath.Dispose()
  }

  $border = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(130, 73, 121, 159), 1)
  $g.DrawPath($border, $track)
  $border.Dispose()
  $trackBrush.Dispose()
  $track.Dispose()
})
$scanPanel.Controls.Add($progress)
Set-RoundedControlRegion -Control $progress -Radius 9

function Set-ProgressValue {
  param([int]$Value)
  $Script:ProgressValue = [Math]::Max(0, [Math]::Min(100, $Value))
  if ($progressPercentLabel) {
    $progressPercentLabel.Text = ('{0}%' -f $Script:ProgressValue)
  }
  if ($progress) {
    $progress.Invalidate()
  }
}

$logTitle = New-Object System.Windows.Forms.Label
$logTitle.Text = 'RUNTIME CONSOLE'
$logTitle.Location = New-Object System.Drawing.Point(50, 662)
$logTitle.Size = New-Object System.Drawing.Size(250, 24)
$logTitle.ForeColor = [System.Drawing.Color]::FromArgb(147, 179, 207)
$logTitle.BackColor = [System.Drawing.Color]::Transparent
$logTitle.Font = New-UiFont -Names @('Bahnschrift', 'Segoe UI') -Size 9.5 -Style ([System.Drawing.FontStyle]::Bold)
$form.Controls.Add($logTitle)

$logFrame = New-Object System.Windows.Forms.Panel
$logFrame.Location = New-Object System.Drawing.Point(36, 690)
$logFrame.Size = New-Object System.Drawing.Size(1048, 112)
$logFrame.BackColor = [System.Drawing.Color]::Transparent
$logFrame.Add_Paint({
  param($sender, $event)
  $g = $event.Graphics
  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
  $rect = New-Object System.Drawing.Rectangle(0, 0, ($sender.Width - 1), ($sender.Height - 1))
  $path = New-RoundedRectanglePath -Rectangle $rect -Radius 16
  $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    $rect,
    [System.Drawing.Color]::FromArgb(246, 1, 5, 9),
    [System.Drawing.Color]::FromArgb(240, 3, 12, 21),
    90
  )
  $border = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(110, 63, 107, 143), 1)
  $g.FillPath($brush, $path)
  $g.DrawPath($border, $path)
  $border.Dispose()
  $brush.Dispose()
  $path.Dispose()
})
$form.Controls.Add($logFrame)
Set-RoundedControlRegion -Control $logFrame -Radius 16

$logBox = New-Object System.Windows.Forms.TextBox
$logBox.Location = New-Object System.Drawing.Point(16, 12)
$logBox.Size = New-Object System.Drawing.Size(1014, 88)
$logBox.Multiline = $true
$logBox.ScrollBars = 'Vertical'
$logBox.ReadOnly = $true
$logBox.BorderStyle = 'None'
$logBox.BackColor = [System.Drawing.Color]::FromArgb(1, 5, 9)
$logBox.ForeColor = [System.Drawing.Color]::FromArgb(224, 235, 246)
$logBox.Font = New-UiFont -Names @('Cascadia Mono', 'Consolas') -Size 9
$logFrame.Controls.Add($logBox)

function Write-UiLog {
  param([string]$Text)
  $line = '[{0}] {1}' -f (Get-Date).ToString('HH:mm:ss'), $Text
  $logBox.AppendText($line + [Environment]::NewLine)
  $status.Text = $Text
}

$Script:ScanProcess = $null
$Script:WorkerProgressPath = ''
$Script:WorkerResultPath = ''
$Script:WorkerErrorPath = ''
$Script:LastProgressLine = 0
$Script:DiscordState = ''
$Script:DiscordId = ''
$Script:DiscordTag = ''
$Script:SessionId = ''
$Script:SessionPublicIp = ''
$Script:MonitorActive = $false
$Script:RuntimeAlertSent = $false
$Script:RuntimeBaselineProcessIds = @{}

function Set-ConnectReady {
  $ready = (-not [string]::IsNullOrWhiteSpace($Script:DiscordId)) -and $consent.Checked
  $busy = $null -ne $Script:ScanProcess -and -not $Script:ScanProcess.HasExited
  $connect.Enabled = $true
  if ($busy) {
    $connect.Text = 'Verifica...'
    $connect.BackColor = [System.Drawing.Color]::FromArgb(44, 65, 84)
    $connect.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    return
  }

  $connect.Text = 'Connetti'
  $connect.Cursor = [System.Windows.Forms.Cursors]::Hand
  if ($ready) {
    $connect.BackColor = [System.Drawing.Color]::FromArgb(0, 127, 214)
    $sessionTileValue.Text = 'PRONTO'
    $sessionTileValue.ForeColor = [System.Drawing.Color]::FromArgb(255, 209, 102)
  } else {
    $connect.BackColor = [System.Drawing.Color]::FromArgb(44, 65, 84)
    $sessionTileValue.Text = if ([string]::IsNullOrWhiteSpace($Script:DiscordId)) { 'IN ATTESA' } else { 'CONSENSO RICHIESTO' }
    $sessionTileValue.ForeColor = [System.Drawing.Color]::FromArgb(238, 245, 252)
  }

  if ([string]::IsNullOrWhiteSpace($Script:DiscordId)) {
    $discordTileValue.Text = 'NON COLLEGATO'
    $discordTileValue.ForeColor = [System.Drawing.Color]::FromArgb(238, 245, 252)
  } else {
    $discordTileValue.Text = 'COLLEGATO'
    $discordTileValue.ForeColor = [System.Drawing.Color]::FromArgb(80, 224, 145)
  }
}

function Get-FinalScanMessage {
  param($Result)

  $count = [int]$Result.findingCount
  if ($count -le 0) {
    return 'Controllo completato! Nessun file sospetto rilevato.'
  }

  $serverName = [string](Get-ConfigValue -Config $config -Name 'serverDisplayName' -Default 'SERVER PROVA')
  $channel = [string](Get-ConfigValue -Config $config -Name 'discordWaitingChannel' -Default 'Attesa Anticheat')
  return ('ATTENZIONE! E'' stato rilevato un file sospetto. Passa in "{0}" sul discord di {1}.' -f $channel, $serverName)
}

function Start-FiveMConnection {
  $autoLaunch = [bool](Get-ConfigValue -Config $config -Name 'autoLaunchFiveM' -Default $true)
  $connectUrl = [string](Get-ConfigValue -Config $config -Name 'fivemConnectUrl' -Default '')
  if (-not $autoLaunch -or [string]::IsNullOrWhiteSpace($connectUrl)) {
    return
  }

  try {
    Write-UiLog ('Apro FiveM e connetto al server: {0}' -f $connectUrl)
    Start-Process $connectUrl | Out-Null
  } catch {
    Write-UiLog ('FiveM non avviato automaticamente: {0}' -f $_.Exception.Message)
  }
}

function Send-AgentHeartbeat {
  param([string]$Status = 'active')

  if ([string]::IsNullOrWhiteSpace($Script:SessionId)) {
    return
  }

  try {
    Send-SentinelSessionHeartbeat -Config $config -SessionId $Script:SessionId -DiscordId $Script:DiscordId -Status $Status -Log {
      param($message)
      Write-UiLog $message
    }
  } catch {
    Write-UiLog ('Heartbeat non riuscito: {0}' -f $_.Exception.Message)
  }
}

function Reset-RuntimeBaseline {
  try {
    $baseline = @{}
    foreach ($process in Get-CimInstance Win32_Process -ErrorAction Stop) {
      $baseline[[string]$process.ProcessId] = $true
    }
    $Script:RuntimeBaselineProcessIds = $baseline
  } catch {
    $Script:RuntimeBaselineProcessIds = @{}
  }
}

function New-RuntimeFinding {
  param(
    [string]$Type,
    [string]$Severity,
    [string]$Signal,
    [string]$Reason,
    [string]$Path = $null,
    [string]$Sha256 = $null
  )

  return [pscustomobject]@{
    type = $Type
    severity = $Severity
    signal = $Signal
    reason = $Reason
    path = ConvertTo-ReportPath $Path
    sha256 = $Sha256
    size = 0
  }
}

function Find-SuspiciousLoadedModule {
  $rules = Get-ConfigValue -Config $signatures -Name 'moduleRules' -Default $null
  if ($null -eq $rules -or $rules.enabled -ne $true) {
    return $null
  }

  try {
    $watchPaths = Resolve-SentinelPathList -Values (Get-ConfigValue -Config $rules -Name 'watchPaths' -Default @())
    foreach ($processName in @((Get-ConfigValue -Config $rules -Name 'processNames' -Default @()))) {
    $nameOnly = [System.IO.Path]::GetFileNameWithoutExtension([string]$processName)
    if ([string]::IsNullOrWhiteSpace($nameOnly)) {
      continue
    }

    $processes = @()
    try {
      $processes = @(Get-Process -Name $nameOnly -ErrorAction SilentlyContinue)
    } catch {
      $processes = @()
    }

    foreach ($process in $processes) {
      $modules = @()
      try {
        $modules = @($process.Modules)
      } catch {
        continue
      }

      foreach ($module in $modules) {
        $modulePath = [string]$module.FileName
        if ([string]::IsNullOrWhiteSpace($modulePath)) {
          continue
        }

        $nameTerm = Test-TermMatch -Text $modulePath -Terms $signatures.suspiciousNames
        $hash = $null
        if ($nameTerm -or (Test-PathMatchesAny -Path $modulePath -Patterns $watchPaths)) {
          $hash = Get-Sha256FileSafe -Path $modulePath -MaxBytes $config.maxFileBytesToHash
        }

        if ($hash -and (@($signatures.knownBadSha256) -contains $hash)) {
          return New-RuntimeFinding -Type 'runtime_module' -Severity 'critical' -Signal $hash -Reason ('Known bad module loaded in {0}' -f $process.ProcessName) -Path $modulePath -Sha256 $hash
        }

        if ($nameTerm) {
          return New-RuntimeFinding -Type 'runtime_module' -Severity 'critical' -Signal $nameTerm -Reason ('Suspicious module loaded in {0}' -f $process.ProcessName) -Path $modulePath -Sha256 $hash
        }

        $extension = [System.IO.Path]::GetExtension($modulePath).ToLowerInvariant()
        $watchedModule = Test-PathMatchesAny -Path $modulePath -Patterns $watchPaths
        if ($watchedModule -and @('.dll', '.asi') -contains $extension -and -not (Test-TrustedPublisher -Path $modulePath -Signatures $signatures)) {
          return New-RuntimeFinding -Type 'runtime_module' -Severity 'high' -Signal 'unsigned_watched_module' -Reason ('Unsigned watched module loaded in {0}' -f $process.ProcessName) -Path $modulePath -Sha256 $hash
        }
      }
    }
    }
  } catch {
    return $null
  }

  return $null
}

function Find-RuntimeSuspiciousProcess {
  $moduleFinding = Find-SuspiciousLoadedModule
  if ($null -ne $moduleFinding) {
    return $moduleFinding
  }

  try {
    $behaviorRules = Get-ConfigValue -Config $signatures -Name 'behaviorRules' -Default $null
    $trackNewProcesses = $null -ne $behaviorRules -and $behaviorRules.trackNewProcesses -eq $true
    $flagUnsignedUserWritable = $null -ne $behaviorRules -and $behaviorRules.flagUnsignedUserWritableProcesses -eq $true
    $userWritablePaths = if ($null -ne $behaviorRules) { Resolve-SentinelPathList -Values (Get-ConfigValue -Config $behaviorRules -Name 'userWritablePaths' -Default @()) } else { @() }

    foreach ($process in Get-CimInstance Win32_Process -ErrorAction Stop) {
      $processId = [string]$process.ProcessId
      $name = [string]$process.Name
      $path = [string]$process.ExecutablePath
      $commandLine = [string]$process.CommandLine
      $isNewProcess = $trackNewProcesses -and -not $Script:RuntimeBaselineProcessIds.ContainsKey($processId)

      $term = Test-TermMatch -Text ($name + ' ' + $path) -Terms $signatures.suspiciousNames
      if (-not $term) {
        $term = Test-TermMatch -Text $commandLine -Terms (Get-ConfigValue -Config $signatures -Name 'runtimeMarkers' -Default @())
      }
      if ($term) {
        $hash = if ($path -and (Test-Path -LiteralPath $path)) { Get-Sha256FileSafe -Path $path -MaxBytes $config.maxFileBytesToHash } else { $null }
        return New-RuntimeFinding -Type 'runtime_process' -Severity 'critical' -Signal $term -Reason 'Suspicious process started while playing' -Path ($(if ($path) { $path } else { $commandLine })) -Sha256 $hash
      }

      if ($isNewProcess -and $flagUnsignedUserWritable -and $path -and -not (Test-IgnoredRuntimeProcess -Name $name -Path $path -Signatures $signatures)) {
        if ((Test-PathMatchesAny -Path $path -Patterns $userWritablePaths) -and -not (Test-TrustedPublisher -Path $path -Signatures $signatures)) {
          $hash = Get-Sha256FileSafe -Path $path -MaxBytes $config.maxFileBytesToHash
          return New-RuntimeFinding -Type 'runtime_behavior' -Severity 'high' -Signal 'new_unsigned_user_writable_process' -Reason 'New unsigned process launched from a user-writable path while playing' -Path $path -Sha256 $hash
        }
      }
    }
  } catch {
    return $null
  }

  return $null
}

function Get-RuntimeAlertMessage {
  $serverName = [string](Get-ConfigValue -Config $config -Name 'serverDisplayName' -Default 'SERVER PROVA')
  $channel = [string](Get-ConfigValue -Config $config -Name 'discordWaitingChannel' -Default 'Attesa Anticheat')
  return ('ATTENZIONE! E'' stata rilevata un''anomalia runtime mentre eri in gioco. Passa in "{0}" sul discord di {1}.' -f $channel, $serverName)
}

function Send-RuntimeAlert {
  param($Finding)

  $machineFingerprint = Get-MachineFingerprint
  $network = Get-LocalNetworkIdentity
  $report = [ordered]@{
    reportId = [guid]::NewGuid().ToString()
    generatedAt = (Get-Date).ToUniversalTime().ToString('o')
    app = @{
      name = $config.appName
      version = $config.version
      scanMode = 'runtime-monitor'
      signatureVersion = $signatures.version
    }
    identity = @{
      machineFingerprint = $machineFingerprint
      userFingerprint = Get-Sha256Text ("sentinel:user:{0}" -f [Environment]::UserName)
      publicIp = $Script:SessionPublicIp
      localIps = $network.localIps
      hostNameHash = Get-Sha256Text ("sentinel:host:{0}" -f $network.hostName)
      discord = @{
        id = $Script:DiscordId
        username = $Script:DiscordTag
      }
    }
    summary = @{
      highestSeverity = 'critical'
      findingCount = 1
      suspicious = $true
      reason = 'runtime suspicious process'
    }
    findings = @($Finding)
  }

  $reportPath = Join-Path $Script:ReportsPath ('{0}.runtime.json' -f $report.reportId)
  $report | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $reportPath -Encoding UTF8
  $envelope = New-EncryptedEnvelope -Payload $report -SharedSecret $config.sharedSecret

  Invoke-SentinelJson -Uri (($config.cloudEndpoint.TrimEnd('/')) + '/v1/agent/alert') -AgentKey $config.agentKey -Body @{
    licenseKey = $config.licenseKey
    sessionId = $Script:SessionId
    machineFingerprint = $machineFingerprint
    discordId = $Script:DiscordId
    envelope = $envelope
  } | Out-Null
}

function Start-PostScanMonitor {
  $Script:MonitorActive = $true
  $Script:RuntimeAlertSent = $false
  Reset-RuntimeBaseline
  $heartbeatTimer.Interval = [Math]::Max(5000, [int](Get-ConfigValue -Config $config -Name 'heartbeatIntervalSeconds' -Default 15) * 1000)
  $monitorTimer.Interval = [Math]::Max(5000, [int](Get-ConfigValue -Config $config -Name 'monitorIntervalSeconds' -Default 10) * 1000)
  $heartbeatTimer.Start()
  $monitorTimer.Start()
  Send-AgentHeartbeat
  $sessionTileValue.Text = 'SESSIONE LIVE'
  $sessionTileValue.ForeColor = [System.Drawing.Color]::FromArgb(80, 224, 145)
  $runtimeTileValue.Text = 'ATTIVO'
  $runtimeTileValue.ForeColor = [System.Drawing.Color]::FromArgb(80, 224, 145)
  Write-UiLog 'Monitor runtime attivo: non chiudere Sentinel mentre giochi.'
}

$consent.Add_CheckedChanged({
  Set-ConnectReady
})

$discordTimer = New-Object System.Windows.Forms.Timer
$discordTimer.Interval = 1800
$discordTimer.Add_Tick({
  if ([string]::IsNullOrWhiteSpace($Script:DiscordState)) {
    $discordTimer.Stop()
    return
  }

  try {
    $response = Invoke-SentinelJson -Uri (($config.cloudEndpoint.TrimEnd('/')) + '/v1/agent/discord/status') -AgentKey $config.agentKey -Body @{
      licenseKey = $config.licenseKey
      state = $Script:DiscordState
    }

    if ($response.linked -eq $true) {
      $Script:DiscordId = [string]$response.discordId
      $Script:DiscordTag = [string]$response.username
      $discordStatus.Text = if ($Script:DiscordTag) { 'Discord: ' + $Script:DiscordTag } else { 'Discord ID: ' + $Script:DiscordId }
      $discordStatus.ForeColor = [System.Drawing.Color]::FromArgb(80, 224, 145)
      $discordTileValue.Text = 'COLLEGATO'
      $discordTileValue.ForeColor = [System.Drawing.Color]::FromArgb(80, 224, 145)
      $discordTimer.Stop()
      Write-UiLog ('Discord collegato: {0}' -f $Script:DiscordId)
      Set-ConnectReady
    }
  } catch {
    $discordStatus.Text = 'Errore login Discord'
  }
})

$discordLogin.Add_Click({
  $Script:DiscordState = [guid]::NewGuid().ToString('N')
  $discordStatus.Text = 'In attesa autorizzazione...'
  $discordStatus.ForeColor = [System.Drawing.Color]::FromArgb(255, 209, 102)
  $discordTileValue.Text = 'AUTORIZZAZIONE'
  $discordTileValue.ForeColor = [System.Drawing.Color]::FromArgb(255, 209, 102)
  $url = ('{0}/auth/discord/start?state={1}' -f $config.cloudEndpoint.TrimEnd('/'), [uri]::EscapeDataString($Script:DiscordState))
  try {
    Start-Process $url | Out-Null
    Write-UiLog 'Login Discord aperto nel browser.'
    $discordTimer.Start()
  } catch {
    [System.Windows.Forms.MessageBox]::Show(('Non riesco ad aprire il login Discord: {0}' -f $_.Exception.Message), 'Sentinel Anticheat') | Out-Null
  }
})

$heartbeatTimer = New-Object System.Windows.Forms.Timer
$heartbeatTimer.Interval = 15000
$heartbeatTimer.Add_Tick({
  if ($Script:MonitorActive) {
    Send-AgentHeartbeat
  }
})

$monitorTimer = New-Object System.Windows.Forms.Timer
$monitorTimer.Interval = 10000
$monitorTimer.Add_Tick({
  if (-not $Script:MonitorActive -or $Script:RuntimeAlertSent) {
    return
  }

  $finding = Find-RuntimeSuspiciousProcess
  if ($null -eq $finding) {
    Write-UiLog 'Monitor runtime: nessun processo sospetto rilevato.'
    return
  }

  $Script:RuntimeAlertSent = $true
  $runtimeTileValue.Text = 'ALERT'
  $runtimeTileValue.ForeColor = [System.Drawing.Color]::FromArgb(255, 91, 91)
  try {
    Send-RuntimeAlert -Finding $finding
    $message = Get-RuntimeAlertMessage
    Write-UiLog $message
    [System.Windows.Forms.MessageBox]::Show($message, 'Sentinel Anticheat') | Out-Null
  } catch {
    Write-UiLog ('Runtime alert non inviato: {0}' -f $_.Exception.Message)
  }
})

function Complete-ScanUi {
  param(
    [bool]$Success,
    [string]$Message
  )

  Set-ProgressValue $(if ($Success) { 100 } else { 0 })
  Set-ConnectReady
  $scanTimer.Stop()

  if (-not $Success) {
    $sessionTileValue.Text = 'ERRORE'
    $sessionTileValue.ForeColor = [System.Drawing.Color]::FromArgb(255, 91, 91)
    $runtimeTileValue.Text = 'STANDBY'
    $runtimeTileValue.ForeColor = [System.Drawing.Color]::FromArgb(238, 245, 252)
  }

  if ($Message) {
    Write-UiLog $Message
  }
}

$scanTimer = New-Object System.Windows.Forms.Timer
$scanTimer.Interval = 700
$scanTimer.Add_Tick({
  if ($Script:WorkerProgressPath -and (Test-Path -LiteralPath $Script:WorkerProgressPath)) {
    $lines = @(Get-Content -LiteralPath $Script:WorkerProgressPath -ErrorAction SilentlyContinue)
    if ($lines.Count -gt $Script:LastProgressLine) {
      for ($index = $Script:LastProgressLine; $index -lt $lines.Count; $index++) {
        $line = [string]$lines[$index]
        if ($line.Trim() -ne '') {
          $displayLine = $line
          $messageText = ($line -replace '^\[[^\]]+\]\s*', '')
          if ($line -match '^\[(?<time>[^\]]+)\]\s+\[progress:(?<percent>\d+)\]\s*(?<message>.*)$') {
            $percent = [Math]::Max(0, [Math]::Min(100, [int]$Matches.percent))
            Set-ProgressValue $percent
            $messageText = $Matches.message
            $displayLine = ('[{0}] {1}' -f $Matches.time, $messageText)
          }

          $logBox.AppendText($displayLine + [Environment]::NewLine)
          $status.Text = $messageText
        }
      }
      $Script:LastProgressLine = $lines.Count
    }
  }

  if ($null -eq $Script:ScanProcess) {
    return
  }

  if (-not $Script:ScanProcess.HasExited) {
    return
  }

  if ($Script:ScanProcess.ExitCode -eq 0 -and (Test-Path -LiteralPath $Script:WorkerResultPath)) {
    $result = Get-Content -LiteralPath $Script:WorkerResultPath -Raw | ConvertFrom-Json
    $Script:SessionId = [string]$result.sessionId
    $Script:SessionPublicIp = [string]$result.publicIp
    $finalMessage = Get-FinalScanMessage $result
    Complete-ScanUi -Success $true -Message $finalMessage
    if ([int]$result.findingCount -le 0) {
      $sessionTileValue.Text = 'SCANSIONE OK'
      $sessionTileValue.ForeColor = [System.Drawing.Color]::FromArgb(80, 224, 145)
      $runtimeTileValue.Text = 'AVVIO MONITOR'
      $runtimeTileValue.ForeColor = [System.Drawing.Color]::FromArgb(255, 209, 102)
      try { $script:signatures = Read-JsonFile $Script:SignaturesPath } catch {}
      Start-PostScanMonitor
      Start-FiveMConnection
    } else {
      $sessionTileValue.Text = 'BLOCCATO'
      $sessionTileValue.ForeColor = [System.Drawing.Color]::FromArgb(255, 91, 91)
      $runtimeTileValue.Text = 'ALERT'
      $runtimeTileValue.ForeColor = [System.Drawing.Color]::FromArgb(255, 91, 91)
      [System.Windows.Forms.MessageBox]::Show($finalMessage, 'Sentinel Anticheat') | Out-Null
    }
    $Script:ScanProcess = $null
    return
  }

  $errorMessage = 'Scansione non completata.'
  if (Test-Path -LiteralPath $Script:WorkerErrorPath) {
    try {
      $errorPayload = Get-Content -LiteralPath $Script:WorkerErrorPath -Raw | ConvertFrom-Json
      $errorMessage = $errorPayload.message
    } catch {}
  }

  Complete-ScanUi -Success $false -Message ('Errore: ' + $errorMessage)
  [System.Windows.Forms.MessageBox]::Show($errorMessage, 'Sentinel Anticheat - Errore') | Out-Null
  $Script:ScanProcess = $null
})

$connect.Add_Click({
  if (-not $consent.Checked) {
    [System.Windows.Forms.MessageBox]::Show('Devi autorizzare la verifica locale per procedere.', 'Sentinel Anticheat') | Out-Null
    return
  }

  if ([string]::IsNullOrWhiteSpace($Script:DiscordId)) {
    [System.Windows.Forms.MessageBox]::Show('Devi collegare Discord prima di connetterti.', 'Sentinel Anticheat') | Out-Null
    return
  }

  if ($null -ne $Script:ScanProcess -and -not $Script:ScanProcess.HasExited) {
    return
  }

  $runId = [guid]::NewGuid().ToString('N')
  $Script:WorkerProgressPath = Join-Path $Script:LogsPath ("scan-{0}.progress.log" -f $runId)
  $Script:WorkerResultPath = Join-Path $Script:LogsPath ("scan-{0}.result.json" -f $runId)
  $Script:WorkerErrorPath = Join-Path $Script:LogsPath ("scan-{0}.error.json" -f $runId)
  $Script:LastProgressLine = 0

  $logBox.Clear()
  $connect.Enabled = $true
  $connect.Text = 'Verifica...'
  $connect.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
  $connect.BackColor = [System.Drawing.Color]::FromArgb(44, 65, 84)
  $sessionTileValue.Text = 'SCANSIONE'
  $sessionTileValue.ForeColor = [System.Drawing.Color]::FromArgb(0, 149, 255)
  $runtimeTileValue.Text = 'CHECK FILE'
  $runtimeTileValue.ForeColor = [System.Drawing.Color]::FromArgb(255, 209, 102)
  Set-ProgressValue 3
  Write-UiLog 'Connessione e scansione avviate...'

  $arguments = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', "`"$PSCommandPath`"",
    '-WorkerScan',
    '-WorkerProgressPath', "`"$Script:WorkerProgressPath`"",
    '-WorkerResultPath', "`"$Script:WorkerResultPath`"",
    '-WorkerErrorPath', "`"$Script:WorkerErrorPath`"",
    '-WorkerDiscordId', "`"$Script:DiscordId`"",
    '-WorkerDiscordTag', "`"$Script:DiscordTag`""
  )

  $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = 'powershell.exe'
  $startInfo.Arguments = ($arguments -join ' ')
  $startInfo.WorkingDirectory = $Script:Root
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
  $Script:ScanProcess = [System.Diagnostics.Process]::Start($startInfo)
  $scanTimer.Start()
})

$form.Add_FormClosing({
  $heartbeatTimer.Stop()
  $monitorTimer.Stop()
  $discordTimer.Stop()
  $Script:MonitorActive = $false

  if (-not [string]::IsNullOrWhiteSpace($Script:SessionId)) {
    Send-AgentHeartbeat -Status 'closing'
  }

  if ($null -ne $Script:ScanProcess -and -not $Script:ScanProcess.HasExited) {
    try { $Script:ScanProcess.Kill() } catch {}
  }
})

Set-ConnectReady
[void]$form.ShowDialog()
