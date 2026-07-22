local function triggerFirewallSmoke()
  print('[Sentinel Test] firewall smoke: triggering honeypots and event spam')

  TriggerServerEvent('sentinel:giveMoney')
  TriggerServerEvent('sentinel:adminBypass')
  TriggerServerEvent('sentinel:spawnVehicle')

  for _ = 1, 40 do
    TriggerServerEvent('sentinel_test:spam_target')
  end
end

RegisterCommand('sentinel_test_firewall', function()
  triggerFirewallSmoke()
end, false)

RegisterCommand('sentinel_test_enforce_kick', function()
  print('[Sentinel Test] enforce kick smoke: requesting server kick')
  TriggerServerEvent('sentinel_test:enforce_kick')
end, false)

local demoCommands = {
  sentinel_demo_spawn_sultan = 'spawn_sultan',
  sentinel_demo_noclip = 'noclip',
  sentinel_demo_goto = 'goto',
  sentinel_demo_tpm = 'tpm',
  sentinel_demo_revive = 'revive'
}

local function triggerDemoAction(action)
  print(('[Sentinel Demo] simulated action requested: %s'):format(action))
  TriggerServerEvent('sentinel_demo:action', action)
end

for commandName, action in pairs(demoCommands) do
  RegisterCommand(commandName, function()
    triggerDemoAction(action)
  end, false)
end
