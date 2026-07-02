# Changelog

## 0.5.1

- Moved private config out of shared client scripts.
- Added client-safe config for heartbeat, movement, weapon, and vehicle checks.
- Fixed cloud decision signature verification compatibility with the local mock.
- Added initial ban storage file for FXServer runtime persistence.
- Added FXServer test harness and cloud smoke test.
- Added `data/runtime_status.json` startup marker for local FXServer validation.
- Added local test autorun and player-side `sentinel_test_self` smoke command.
- Added firewall smoke command for honeypot and event-spam validation.
- Added guarded one-shot enforce kick smoke test for local validation.

## 0.5.0

- Added startup preflight checks for privacy, cloud, framework, mode, and economy configuration.
- Added `sentinel_preflight` admin command.
- Fixed startup log version reporting.
- Added `sentinel_test_resource` manual FXServer smoke-test helper.
- Added production readiness checklist.

## 0.4.1

- Clean Windows package layout.

## 0.4.0

- Added ESX and QBCore framework account snapshots.
- Added server-side account delta detection for cash and bank.
- Added protected job transition detection.
- Added admin action guard export.
- Added ESX/QBCore integration examples.
- Added persistent hashed ban storage.
- Added Sentinel Cloud mock dashboard and health endpoint.

## 0.3.0

- Added economy guard exports for money, items, and jobs.
- Added cloud decision enforcement in `enforce` mode.
- Added hashed ban persistence.

## 0.2.0

- Added Sentinel Cloud mock API.
- Added license verification and pseudonymized telemetry.

## 0.1.0

- Initial FiveM anticheat resource scaffold.
