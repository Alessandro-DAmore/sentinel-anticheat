Sentinel = Sentinel or {}
Sentinel.Adapters = Sentinel.Adapters or {}

local function getQBCore()
  local resource = Config.Framework.resourceName or 'qb-core'
  local ok, qb = pcall(function()
    return exports[resource]:GetCoreObject()
  end)

  if ok then
    return qb
  end

  return nil
end

local function getPlayer(source)
  local qb = getQBCore()
  if not qb then
    return nil
  end

  return qb.Functions.GetPlayer(source)
end

Sentinel.Adapters.qbcore = {
  name = 'qbcore',
  isAdmin = function(source)
    local qb = getQBCore()
    if not qb then
      return IsPlayerAceAllowed(source, 'sentinel.admin')
    end

    return qb.Functions.HasPermission(source, 'admin') or IsPlayerAceAllowed(source, 'sentinel.admin')
  end,
  snapshot = function(source)
    local player = getPlayer(source)
    if not player or not player.PlayerData then
      return nil
    end

    local money = player.PlayerData.money or {}
    local job = player.PlayerData.job or {}
    return {
      cash = tonumber(money[Config.FrameworkGuards.qbcore.accountNames.cash] or 0) or 0,
      bank = tonumber(money[Config.FrameworkGuards.qbcore.accountNames.bank] or 0) or 0,
      crypto = tonumber(money[Config.FrameworkGuards.qbcore.accountNames.crypto] or 0) or 0,
      job = job.name
    }
  end
}
