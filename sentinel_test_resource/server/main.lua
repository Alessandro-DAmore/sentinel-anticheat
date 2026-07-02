local function requireConsole(source)
  if source ~= 0 then
    print('[Sentinel Test] commands must be run from the server console')
    return false
  end

  return true
end

local function runSmoke(target, context)
  context = context or 'sentinel_test_smoke'

  local moneyAllowed = exports.sentinel_ac:GuardMoney(target, 999999, 'cash', context .. ':money')
  print(('[Sentinel Test] GuardMoney allowed=%s amount=999999'):format(tostring(moneyAllowed)))

  local itemAllowed = exports.sentinel_ac:GuardItem(target, 'weapon_rpg', 1, context .. ':item')
  print(('[Sentinel Test] GuardItem allowed=%s item=weapon_rpg amount=1'):format(tostring(itemAllowed)))

  local adminAllowed = exports.sentinel_ac:AuthorizeAdminAction(target, 'give_item', context .. ':admin')
  print(('[Sentinel Test] AuthorizeAdminAction allowed=%s action=give_item'):format(tostring(adminAllowed)))
end

RegisterCommand('sentinel_test_money', function(source, args)
  if not requireConsole(source) then
    return
  end

  local target = tonumber(args[1])
  local amount = tonumber(args[2]) or 999999

  if not target then
    print('[Sentinel Test] usage: sentinel_test_money <playerId> <amount>')
    return
  end

  local allowed = exports.sentinel_ac:GuardMoney(target, amount, 'cash', 'sentinel_test_money')
  print(('[Sentinel Test] GuardMoney allowed=%s amount=%s'):format(tostring(allowed), amount))
end, true)

RegisterCommand('sentinel_test_item', function(source, args)
  if not requireConsole(source) then
    return
  end

  local target = tonumber(args[1])
  local item = args[2] or 'weapon_rpg'
  local amount = tonumber(args[3]) or 1

  if not target then
    print('[Sentinel Test] usage: sentinel_test_item <playerId> <item> <amount>')
    return
  end

  local allowed = exports.sentinel_ac:GuardItem(target, item, amount, 'sentinel_test_item')
  print(('[Sentinel Test] GuardItem allowed=%s item=%s amount=%s'):format(tostring(allowed), item, amount))
end, true)

RegisterCommand('sentinel_test_admin', function(source, args)
  if not requireConsole(source) then
    return
  end

  local target = tonumber(args[1])
  local action = args[2] or 'give_item'

  if not target then
    print('[Sentinel Test] usage: sentinel_test_admin <playerId> <action>')
    return
  end

  local allowed = exports.sentinel_ac:AuthorizeAdminAction(target, action, 'sentinel_test_admin')
  print(('[Sentinel Test] AuthorizeAdminAction allowed=%s action=%s'):format(tostring(allowed), action))
end, true)

RegisterCommand('sentinel_test_self', function(source)
  if source == 0 then
    print('[Sentinel Test] usage from console: sentinel_test_money <playerId> <amount>')
    return
  end

  runSmoke(source, 'sentinel_test_self')
end, false)

RegisterCommand('sentinel_test_event_spam', function(source, args)
  if not requireConsole(source) then
    return
  end

  local target = tonumber(args[1])
  if not target then
    print('[Sentinel Test] usage: sentinel_test_event_spam <playerId>')
    return
  end

  print('[Sentinel Test] Event spam must be tested from a client script or cheat simulation, not server console.')
end, true)

RegisterNetEvent('sentinel_test:spam_target', function()
  local allowed = exports.sentinel_ac:InspectEvent(source, 'sentinel_test:spam_target')
  if not allowed then
    CancelEvent()
    print(('[Sentinel Test] spam target blocked source=%s'):format(source))
  end
end)

RegisterNetEvent('sentinel_test:enforce_kick', function()
  local ok, message = exports.sentinel_ac:RunEnforceKickTest(source)
  print(('[Sentinel Test] enforce kick source=%s ok=%s message=%s'):format(
    source,
    tostring(ok),
    tostring(message)
  ))
end)

CreateThread(function()
  if GetConvar('sentinel_test_autorun', 'false') ~= 'true' then
    return
  end

  local ran = false
  while not ran do
    Wait(2000)

    for _, player in ipairs(GetPlayers()) do
      local target = tonumber(player)
      if target then
        ran = true
        print(('[Sentinel Test] autorun smoke for player=%s'):format(target))
        runSmoke(target, 'sentinel_test_autorun')
        break
      end
    end
  end
end)
