# Sentinel Suite Windows Quickstart

## FiveM resource

1. Extract `sentinel_ac` into your FXServer `resources` folder.
2. Edit `sentinel_ac/config.lua`.
3. Set:

```lua
Config.Framework.type = 'esx' -- or qbcore, vrp, standalone
Config.Product.mode = 'monitor'
```

`sentinel_ac/config.lua` is server-only and contains secrets. Do not add it to `shared_scripts`.
Client-safe values live in `sentinel_ac/shared/client_config.lua`.

4. Add to `server.cfg`:

```cfg
ensure sentinel_ac
ensure sentinel_test_resource
add_ace group.admin sentinel.admin allow
```

5. Start the server and watch the console for:

```text
[Sentinel AC] loaded
```

## Cloud mock

The cloud mock requires Node.js 18+.

```powershell
cd sentinel_cloud_mock
npm run dev
```

Smoke test:

```powershell
npm run smoke
```

Then open:

```text
http://127.0.0.1:8787/dashboard?token=CHANGE_ME_DASHBOARD_TOKEN
```

Admin reports for desktop agent scans:

```text
http://127.0.0.1:8787/admin/reports?token=CHANGE_ME_DASHBOARD_TOKEN
```

## Desktop agent MVP

Run the local desktop app:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "E:\Sentinel_Anticheat\sentinel_desktop\Run-SentinelAnticheat.ps1"
```

The `Connetti` button starts a consent-based PC scan, encrypts the report, and uploads it to the Sentinel Cloud mock. Suspicious findings include metadata and SHA-256 hashes, not raw personal files.

## Production order

1. Keep `monitor` mode for testing.
2. Tune `Config.Economy` limits per server.
3. Add guards inside reward/shop/job scripts.
4. Enable webhooks.
5. Enable cloud after setting unique secrets.
6. Switch selected punishments to `enforce` after reviewing false positives.

Run this command in the FXServer console after startup:

```cfg
sentinel_preflight
```

The resource also writes a startup marker:

```text
sentinel_ac/data/runtime_status.json
```

Read `PRODUCTION_READINESS.md` before proposing the product to a real server.

## Local FXServer harness

If you do not already have an FXServer, create a local test server:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "E:\Sentinel_Anticheat\tools\Setup-LocalFXServer.ps1"
```

Then edit:

```text
E:\Sentinel_Anticheat\fxserver_local\server-data\sentinel.server.cfg
```

and replace `CHANGE_ME_FIVEM_LICENSE_KEY` with your free Cfx.re license key.

Start the local server:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "E:\Sentinel_Anticheat\fxserver_local\Run-SentinelFXServer.ps1"
```

If you already have server-data, use `fxserver_test/server.cfg` as a monitor-mode template.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "E:\Sentinel_Anticheat\tools\Install-FXServerResources.ps1" -ServerDataPath "C:\path\to\server-data" -Force
```

## Manual smoke tests

After a player joins, use their server ID:

```cfg
sentinel_test_money 1 999999
sentinel_test_item 1 weapon_rpg 1
sentinel_test_admin 1 give_item
```

These commands should create monitor/enforcement detections depending on `Config.Product.mode`.

For cloud/local autorun testing, set `sentinel_test_autorun true` in the test `server.cfg`.
Players can also run this smoke test from chat/F8:

```cfg
sentinel_test_self
```

Firewall smoke test from F8:

```cfg
sentinel_test_firewall
```

Expected detections: `blocked_event` for honeypots and `event_spam` for repeated protected event calls.

Controlled enforce kick test from F8:

```cfg
sentinel_test_enforce_kick
```

This requires `set sentinel_test_allow_enforce true` and temporarily enforces one money exploit detection before returning the resource to monitor mode.

