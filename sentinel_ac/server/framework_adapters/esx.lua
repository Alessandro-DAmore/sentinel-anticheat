Sentinel = Sentinel or {}
Sentinel.Adapters = Sentinel.Adapters or {}

local function getESX()
  local resource = Config.Framework.resourceName or 'es_extended'
  local ok, esx = pcall(function()
    return exports[resource]:getSharedObject()
  end)

  if ok then
    return esx
  end

  return nil
end

local function getPlayer(source)
  local esx = getESX()
  if not esx then
    return nil
  end

  return esx.GetPlayerFromId(source)
end

Sentinel.Adapters.esx = {
  name = 'esx',
  isAdmin = function(source)
    local player = getPlayer(source)
    if not player then
      return IsPlayerAceAllowed(source, 'sentinel.admin')
    end

    local group = player and player.getGroup and player.getGroup()
    return group == 'admin' or group == 'superadmin' or IsPlayerAceAllowed(source, 'sentinel.admin')
  end,
  snapshot = function(source)
    local player = getPlayer(source)
    if not player then
      return nil
    end

    local cash = player.getMoney and player.getMoney() or 0
    local bank = 0
    local black = 0

    if player.getAccount then
      local bankAccount = player.getAccount(Config.FrameworkGuards.esx.accountNames.bank)
      local blackAccount = player.getAccount(Config.FrameworkGuards.esx.accountNames.black)
      bank = bankAccount and bankAccount.money or 0
      black = blackAccount and blackAccount.money or 0
    end

    local job = player.getJob and player.getJob() or nil
    return {
      cash = tonumber(cash) or 0,
      bank = tonumber(bank) or 0,
      black = tonumber(black) or 0,
      job = job and job.name or nil
    }
  end
}
