SentinelClient = SentinelClient or {}

CreateThread(function()
  while true do
    Wait(Config.Movement.checkIntervalMs)

    if Config.Modules.movementChecks then
      local ped = PlayerPedId()
      local coords = GetEntityCoords(ped)
      local speed = GetEntitySpeed(ped)

      TriggerServerEvent('sentinel:movement', {
        x = coords.x,
        y = coords.y,
        z = coords.z
      }, speed, IsPedInAnyVehicle(ped, false))
    end
  end
end)
