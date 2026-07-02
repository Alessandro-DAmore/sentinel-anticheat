SentinelClient = SentinelClient or {}

local function currentWeaponName()
  local ped = PlayerPedId()
  local weapon = GetSelectedPedWeapon(ped)

  for _, weaponName in ipairs(Config.Weapons.blacklisted or {}) do
    if weapon == GetHashKey(weaponName) then
      return weaponName
    end
  end

  return nil
end

function SentinelClient.sendHeartbeat()
  local ped = PlayerPedId()
  local payload = {
    health = GetEntityHealth(ped),
    armor = GetPedArmour(ped),
    godmode = GetPlayerInvincible(PlayerId()),
    blacklistedWeapon = currentWeaponName()
  }

  TriggerServerEvent('sentinel:heartbeat', payload)
end

CreateThread(function()
  while true do
    Wait(Config.Heartbeat.intervalMs)
    SentinelClient.sendHeartbeat()
  end
end)
