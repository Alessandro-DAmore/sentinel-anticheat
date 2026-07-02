# Sentinel Anticheat Desktop

MVP Windows desktop agent for Sentinel Anticheat.

## What it does

- Shows a consent-based desktop UI.
- Requires a Discord link before `Connetti`.
- Runs scans in a hidden worker process so the window stays responsive.
- Runs local checks for suspicious processes, services, drivers, and high-risk file locations.
- Keeps a runtime heartbeat open while the player is in FiveM.
- Opens FiveM with the configured `fivem://connect/...` URL after a clean check.
- Detects public IP from the Sentinel Cloud connection and local private IPs from the PC.
- Uploads only an encrypted JSON report.
- Sends suspicious file metadata and hashes, not raw personal files.

## Run

Start the local cloud mock first:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "E:\Sentinel_Anticheat\fxserver_local\Run-SentinelCloudMock.ps1"
```

Then run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "E:\Sentinel_Anticheat\sentinel_desktop\Run-SentinelAnticheat.ps1"
```

The app keeps scan progress inside the UI; it does not open a visible PowerShell prompt during normal use.

Discord login is simulated by the local cloud mock in this dev build:

```text
http://127.0.0.1:8787/auth/discord/start
```

Admin reports:

```text
http://127.0.0.1:8787/admin
```

## Build Windows EXE

Development build:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "E:\Sentinel_Anticheat\sentinel_desktop\Build-SentinelDesktopExe.ps1"
```

Signed production build:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "E:\Sentinel_Anticheat\sentinel_desktop\Build-SentinelDesktopExe.ps1" -SigningPfx "C:\path\sentinel-code-signing.pfx" -SigningPassword "PFX_PASSWORD"
```

Windows SmartScreen trust is based on publisher signature and reputation. A local unsigned `.exe` can still show the blue "Esegui comunque" warning even when it is safe. For production, buy a real Code Signing certificate, sign every build, timestamp the signature, and submit false positives to Microsoft Security Intelligence if Defender flags a clean release.

## Production rules

- Replace the shared secret with asymmetric encryption before real customers.
- Replace the local Discord simulator with official Discord OAuth2.
- Sign the Windows executable with a valid Code Signing certificate.
- Use signed signature updates.
- Add a real database and admin authentication.
- Keep full file contents local; report hashes and metadata only unless the user explicitly submits a file for review.
