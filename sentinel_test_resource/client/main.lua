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
