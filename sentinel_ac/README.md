# Sentinel AC

Sentinel AC is a modular FiveM anticheat resource for RP servers.

## Install

1. Copy `sentinel_ac` into your FiveM `resources` folder.
2. Edit `config.lua`.
3. Set `Config.Framework.type` to `standalone`, `esx`, `qbcore`, or `vrp`.
4. Add this to `server.cfg`:

```cfg
ensure sentinel_ac
add_ace group.admin sentinel.admin allow
```

## Windows 32/64 bit

This package is not a native Windows executable. It is a FiveM resource written in Lua, so it is architecture-independent and works on Windows servers through the FiveM runtime.

## Privacy model

Sentinel AC does not need to expose raw identifiers in Discord logs or admin status output. Identifiers are fingerprinted with a server secret before storage.

`config.lua` is loaded only as a server script. Keep privacy secrets, webhook URLs, cloud license keys, and shared cloud secrets out of shared/client scripts.

Important limitation: no local-only system can guarantee that a machine administrator can never access the key, because the server must read the key to verify players. For stronger commercial privacy, move the secret to an external license/API service and return only signed decisions to the resource.

## Production checklist

- Change `Config.Privacy.serverSecret`.
- Change `Config.Cloud.sharedSecret`, `licenseKey`, and `serverKey`.
- Enable webhooks only after setting a private Discord webhook.
- Start in `Config.Product.mode = 'monitor'`.
- Review false positives for at least 48 hours.
- Switch to `enforce` module by module.
- Add framework-specific economy and inventory rules for the target server.

## Admin commands

```cfg
sentinel_status
sentinel_preflight
sentinel_unban <fingerprint>
```

Bans are stored in `sentinel_ac/data/bans.json` with hashed identifiers.

## Sentinel Cloud

Set `Config.Cloud.enabled = true` to send pseudonymized detections to an external Sentinel Cloud API.

The local resource sends only fingerprints and hashed details. The cloud can return a signed decision:

- `allow`
- `warn`
- `kick`
- `ban`

For production, keep secrets outside public support screenshots and rotate them per customer.

## Economy guard integration

Use the exports inside custom reward scripts before giving money, items, or protected jobs.

```lua
local src = source
local amount = 12000

if not exports.sentinel_ac:GuardMoney(src, amount, 'cash', 'pizza_job:reward') then
  return
end

-- Give money only after Sentinel approves the payload.
```

```lua
local src = source
local item = 'bread'
local count = 3

if not exports.sentinel_ac:GuardItem(src, item, count, 'shop:purchase') then
  return
end
```

You can also configure `Config.Economy.protectedEvents` for simple existing events, but direct exports are safer because they let the target script stop before granting the reward.

## Admin guard integration

Use this before sensitive admin actions in custom menus.

```lua
local src = source

if not exports.sentinel_ac:AuthorizeAdminAction(src, 'give_item', 'admin_menu') then
  return
end
```
