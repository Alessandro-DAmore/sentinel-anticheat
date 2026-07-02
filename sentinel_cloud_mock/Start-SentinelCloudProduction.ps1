param(
  [string]$EnvFile = '.env.production'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$envPath = Join-Path $root $EnvFile

if (-not (Test-Path -LiteralPath $envPath)) {
  throw "File env non trovato: $envPath. Copia .env.production.example in .env.production e compila i valori reali."
}

Get-Content -LiteralPath $envPath | ForEach-Object {
  $line = $_.Trim()
  if ($line -eq '' -or $line.StartsWith('#')) {
    return
  }

  $parts = $line.Split('=', 2)
  if ($parts.Count -eq 2) {
    [Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), 'Process')
  }
}

Push-Location $root
try {
  node .\src\server.mjs
} finally {
  Pop-Location
}
