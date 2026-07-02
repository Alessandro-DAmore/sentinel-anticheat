Sentinel = Sentinel or {}
Sentinel.License = Sentinel.License or {}

local state = {
  valid = not Config.Cloud.enabled,
  plan = 'local',
  checkedAt = 0,
  message = 'cloud disabled'
}

function Sentinel.License.state()
  return Sentinel.copyTable(state)
end

function Sentinel.License.verify(callback)
  if not Config.Cloud.enabled then
    state.valid = true
    state.plan = 'local'
    state.message = 'cloud disabled'
    if callback then callback(true, state) end
    return
  end

  Sentinel.Cloud.request('/v1/license/verify', {
    product = Config.Product.name,
    framework = Sentinel.Framework.current(),
    version = GetResourceMetadata(GetCurrentResourceName(), 'version', 0) or 'unknown'
  }, function(ok, response, err)
    state.checkedAt = os.time()

    if not ok then
      state.valid = Config.Cloud.failMode ~= 'block'
      state.message = err
      if callback then callback(state.valid, state) end
      return
    end

    state.valid = response.valid == true
    state.plan = response.plan or 'unknown'
    state.message = response.message or 'verified'

    if callback then callback(state.valid, state) end
  end)
end

CreateThread(function()
  Wait(2500)

  while true do
    Sentinel.License.verify(function(valid, current)
      if not valid then
        print('[Sentinel AC] license invalid: ' .. tostring(current.message))
      else
        print('[Sentinel AC] license state: ' .. tostring(current.message))
      end
    end)

    Wait(Config.Cloud.verifyIntervalMs)
  end
end)
