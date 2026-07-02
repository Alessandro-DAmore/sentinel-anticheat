local version = GetResourceMetadata(GetCurrentResourceName(), 'version', 0) or 'unknown'

local function writeRuntimeStatus()
  SaveResourceFile(GetCurrentResourceName(), 'data/runtime_status.json', json.encode({
    loaded = true,
    version = version,
    framework = Sentinel.Framework.current(),
    mode = Config.Product.mode,
    license = Sentinel.License.state(),
    preflight = Sentinel.Preflight.summary(),
    writtenAt = os.time()
  }), -1)
end

Sentinel.Preflight.run()
writeRuntimeStatus()

print(('[Sentinel AC] loaded v%s framework=%s mode=%s'):format(
  version,
  Sentinel.Framework.current(),
  Config.Product.mode
))

RegisterCommand('sentinel_status', function(source)
  if source ~= 0 and not Sentinel.isAdmin(source) then
    return
  end

  print(('[Sentinel AC] framework=%s mode=%s bans=%s'):format(
    Sentinel.Framework.current(),
    Config.Product.mode,
    json.encode(Sentinel.Storage.allBans())
  ))

  writeRuntimeStatus()
  print('[Sentinel AC] license=' .. json.encode(Sentinel.License.state()))
  print('[Sentinel AC] preflight=' .. json.encode(Sentinel.Preflight.summary()))
end, true)

RegisterCommand('sentinel_preflight', function(source)
  if source ~= 0 and not Sentinel.isAdmin(source) then
    return
  end

  Sentinel.Preflight.run()
  writeRuntimeStatus()
end, true)

RegisterCommand('sentinel_unban', function(source, args)
  if source ~= 0 and not Sentinel.isAdmin(source) then
    return
  end

  local fingerprint = args[1]
  if not fingerprint or fingerprint == '' then
    print('[Sentinel AC] usage: sentinel_unban <fingerprint>')
    return
  end

  Sentinel.Storage.removeBan(fingerprint)
  print('[Sentinel AC] unbanned fingerprint=' .. fingerprint)
end, true)

exports('RunEnforceKickTest', function(source)
  if GetConvar('sentinel_test_allow_enforce', 'false') ~= 'true' then
    return false, 'sentinel_test_allow_enforce disabled'
  end

  local target = tonumber(source)
  if not target or target <= 0 then
    return false, 'invalid source'
  end

  local previousMode = Config.Product.mode
  Config.Product.mode = 'enforce'

  local ok, allowed = pcall(function()
    return Sentinel.Economy.guardMoney(
      target,
      Config.Economy.maxCashReward + 1,
      'cash',
      'sentinel_test_enforce_kick'
    )
  end)

  Config.Product.mode = previousMode
  writeRuntimeStatus()

  if not ok then
    return false, tostring(allowed)
  end

  return allowed == false, 'kick requested'
end)
