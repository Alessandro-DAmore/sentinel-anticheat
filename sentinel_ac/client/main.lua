CreateThread(function()
  Wait(2500)
  TriggerServerEvent('sentinel:heartbeat', {
    started = true
  })
end)
