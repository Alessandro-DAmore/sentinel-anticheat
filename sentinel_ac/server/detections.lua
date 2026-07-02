Sentinel = Sentinel or {}
Sentinel.Detections = Sentinel.Detections or {}

local lastPosition = {}
local lastHeartbeat = {}

RegisterNetEvent('sentinel:heartbeat', function(payload)
  local source = source
  if not Config.Modules.heartbeat then
    return
  end

  lastHeartbeat[source] = Sentinel.nowMs()

  if type(payload) ~= 'table' then
    Sentinel.Punishments.apply(source, 'heartbeat_lost', 'invalid heartbeat')
    return
  end

  if Config.Modules.weaponGuard and payload.blacklistedWeapon then
    Sentinel.Punishments.apply(source, 'blacklisted_weapon', payload.blacklistedWeapon)
  end

  if Config.Modules.vehicleGuard and payload.blacklistedVehicle then
    Sentinel.Punishments.apply(source, 'blacklisted_vehicle', payload.blacklistedVehicle)
  end

  if payload.godmode then
    Sentinel.Punishments.apply(source, 'godmode', 'client reported invincible')
  end
end)

RegisterNetEvent('sentinel:movement', function(coords, speed, inVehicle)
  local source = source
  if not Config.Modules.movementChecks then
    return
  end

  if Config.Movement.ignoreAdminGroups and Sentinel.isAdmin(source) then
    return
  end

  if type(coords) ~= 'table' or not coords.x or not coords.y or not coords.z then
    return
  end

  local previous = lastPosition[source]
  lastPosition[source] = coords

  local maxSpeed = inVehicle and Config.Movement.maxVehicleSpeed or Config.Movement.maxOnFootSpeed
  if speed and speed > maxSpeed then
    Sentinel.Punishments.apply(source, 'speedhack', ('%.2f'):format(speed))
  end

  if previous then
    local dx = coords.x - previous.x
    local dy = coords.y - previous.y
    local dz = coords.z - previous.z
    local distance = math.sqrt(dx * dx + dy * dy + dz * dz)

    if distance > Config.Movement.maxTeleportDistance then
      Sentinel.Punishments.apply(source, 'suspicious_teleport', ('%.2fm'):format(distance))
    end
  end
end)

CreateThread(function()
  while true do
    Wait(Config.Heartbeat.timeoutMs)

    if Config.Modules.heartbeat then
      local now = Sentinel.nowMs()
      for _, player in ipairs(GetPlayers()) do
        local source = tonumber(player)
        local last = lastHeartbeat[source] or now
        if now - last > Config.Heartbeat.timeoutMs then
          Sentinel.Punishments.apply(source, 'heartbeat_lost', 'timeout')
        end
      end
    end
  end
end)

AddEventHandler('playerDropped', function()
  local source = source
  lastPosition[source] = nil
  lastHeartbeat[source] = nil
end)
