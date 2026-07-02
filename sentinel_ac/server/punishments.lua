Sentinel = Sentinel or {}
Sentinel.Punishments = Sentinel.Punishments or {}

local function punishmentFor(code)
  return Config.Punishments[code] or Config.Punishments.default or 'log'
end

local function executeAction(source, action, reason, fingerprint)
  if action == 'warn' then
    Sentinel.Storage.addWarning(fingerprint, {
      reason = reason,
      at = os.time()
    })
    return
  end

  if action == 'kick' then
    DropPlayer(source, 'Sentinel AC: ' .. reason)
    return
  end

  if action == 'ban' then
    Sentinel.Bans.ban(source, reason)
  end
end

function Sentinel.Punishments.apply(source, code, detail)
  local action = punishmentFor(code)
  local player = Sentinel.Privacy.publicPlayerRecord(source)
  local reason = Sentinel.reasonText(code, detail)

  Sentinel.Telemetry.report(source, code, detail, action, function(decision)
    if decision and decision.action and decision.action ~= 'allow' then
      print(('[Sentinel AC] cloud decision %s for %s confidence=%s'):format(
        decision.action,
        player.fingerprint,
        tostring(decision.confidence)
      ))

      if Config.Product.mode == 'enforce' then
        executeAction(source, decision.action, 'cloud:' .. tostring(decision.reason or reason), player.fingerprint)
      end
    end
  end)

  Sentinel.Webhooks.send('Detection', {
    player = player.name,
    fingerprint = player.fingerprint,
    action = action,
    reason = reason
  })

  if Config.Product.mode ~= 'enforce' and action ~= 'log' then
    print(('[Sentinel AC] monitor mode: would %s %s for %s'):format(action, source, reason))
    return
  end

  executeAction(source, action, reason, player.fingerprint)
end
