# Sentinel Suite Production Readiness

This file tracks what is still required before Sentinel can be treated as production-ready for a real RP server.

## Current status

Sentinel is now an installable FiveM resource with:

- server-side event firewall
- heartbeat and movement checks
- entity and explosion protection
- privacy-safe identifier fingerprints
- persistent hashed bans
- ESX/QBCore account snapshots
- economy guard exports
- admin action guard exports
- cloud license and telemetry client
- local Sentinel Cloud mock with dashboard
- server-only private config with client-safe shared config
- local FXServer test harness files

## Required before a live server

1. Run inside FXServer.
   - Start with `Config.Product.mode = 'monitor'`.
   - Fix any runtime API issue shown in the console.
   - Confirm `sentinel_status` and `sentinel_preflight` work.

2. Tune the target framework.
   - Set `Config.Framework.type`.
   - Set `Config.Framework.resourceName` if ESX/QBCore has a custom resource name.
   - Confirm account names for cash, bank, and black money.

3. Integrate reward scripts.
   - Add `GuardMoney` before every reward payout.
   - Add `GuardItem` before every item grant.
   - Add `GuardJob` before protected job changes.
   - Add `AuthorizeAdminAction` before admin menu actions.

4. Tune false positives.
   - Keep monitor mode for at least 48 hours.
   - Review Discord/cloud logs.
   - Raise or lower `Config.Economy` limits per server economy.
   - Tune movement limits for custom vehicles and jobs.

5. Replace development secrets.
   - Change `Config.Privacy.serverSecret`.
   - Change all `Config.Cloud` keys.
   - Never reuse secrets across customers.

6. Move from mock cloud to real cloud.
   - Add a database.
   - Add customer accounts and per-server licenses.
   - Add rate limits.
   - Add audit logs.
   - Use asymmetric signatures for decisions.
   - Add HTTPS and deployment monitoring.

7. Build a real dashboard.
   - Server list.
   - Detections by severity.
   - Player fingerprint history.
   - Ban and appeal workflow.
   - License status.
   - Config templates per framework.

8. Package for customers.
   - Separate public config from private secrets.
   - Add an installation guide.
   - Add a support checklist.
   - Add a changelog and version policy.

## Windows runtime validation

- Local FXServer installed at `E:\Sentinel_Anticheat\fxserver_local`.
- `sentinel_ac` started successfully and wrote `data/runtime_status.json`.
- Preflight currently reports `0` failures in monitor mode.
- Local Sentinel Cloud mock received pseudonymized detection telemetry from FXServer.
- Player smoke tests confirmed money, item, admin, and repeated economy strike detections in monitor mode.
- Firewall smoke tests confirmed honeypot `blocked_event` and repeated-event `event_spam` detections in monitor mode.
- Controlled one-shot enforce kick test confirmed real disconnect behavior without persisting a ban.
- Desktop agent MVP created with consent UI, local scanner, encrypted report upload, local/public IP capture, and Admin Reports page.
- Zero-knowledge report mode added for desktop reports: local files and uploads are encrypted before storage, with admin public-key wrapping.
- Expected development warnings remain for placeholder privacy secret, disabled cloud, and missing real economy integrations.

## Not production-ready yet

- A local FXServer test environment was created at `E:\Sentinel_Anticheat\fxserver_local`.
- Player-connected smoke tests still need to be run from a FiveM client.
- The cloud API is still a local mock.
- Desktop agent packaging is still PowerShell/zip MVP, not a signed Windows installer.
- Admin Reports are in-memory in the mock cloud; production needs database, auth, audit logs, and asymmetric encryption.
- Production zero-knowledge requires keeping the report private key outside Render/cloud hosting and using a separate admin decrypt workflow.
- Ban persistence is file-based, not database-backed.
- ESX/QBCore integration still needs testing against the exact versions used by the target server.
- Client-side checks are basic and should be treated as signals, not proof.
- Strong privacy requires a real external service with proper key management.

## Recommended next build

Version `0.6.0` should focus on FXServer runtime validation and a test resource that simulates:

- normal player heartbeat
- event spam
- money reward accepted
- money reward blocked
- item reward accepted
- admin action blocked
- ban persistence after restart

The package already includes `sentinel_test_resource` as the first manual smoke-test helper.
