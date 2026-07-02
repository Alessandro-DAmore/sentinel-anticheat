SentinelClient = SentinelClient or {}

CreateThread(function()
  while true do
    Wait(2500)

    if Config.Modules.vehicleGuard then
      local ped = PlayerPedId()
      local vehicle = GetVehiclePedIsIn(ped, false)

      if vehicle ~= 0 and GetPedInVehicleSeat(vehicle, -1) == ped then
        local model = GetEntityModel(vehicle)
        for _, modelName in ipairs(Config.Entities.blacklistedModels or {}) do
          if model == GetHashKey(modelName) then
            DeleteEntity(vehicle)
            TriggerServerEvent('sentinel:heartbeat', {
              blacklistedVehicle = modelName
            })
          end
        end
      end
    end
  end
end)
