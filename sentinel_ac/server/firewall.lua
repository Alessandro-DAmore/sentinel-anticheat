Sentinel = Sentinel or {}
Sentinel.Firewall = Sentinel.Firewall or {}

local eventWindows = {}

local function bump(source, eventName)
  local now = Sentinel.nowMs()
  eventWindows[source] = eventWindows[source] or {}
  local bucket = eventWindows[source][eventName] or { startedAt = now, count = 0 }

  if now - bucket.startedAt > Config.Firewall.windowMs then
    bucket.startedAt = now
    bucket.count = 0
  end

  bucket.count = bucket.count + 1
  eventWindows[source][eventName] = bucket
  return bucket.count
end

function Sentinel.Firewall.inspect(source, eventName)
  if not Config.Modules.eventFirewall then
    return true
  end

  if Sentinel.tableHasValue(Config.Firewall.blockedEvents, eventName) then
    Sentinel.Punishments.apply(source, 'blocked_event', eventName)
    return false
  end

  if Sentinel.tableHasValue(Config.Firewall.honeypotEvents, eventName) then
    Sentinel.Punishments.apply(source, 'blocked_event', 'honeypot:' .. eventName)
    return false
  end

  local count = bump(source, eventName)
  if count > Config.Firewall.maxEventsPerWindow then
    Sentinel.Punishments.apply(source, 'event_spam', eventName)
    return false
  end

  return true
end

for _, eventName in ipairs(Config.Firewall.blockedEvents) do
  RegisterNetEvent(eventName, function()
    Sentinel.Firewall.inspect(source, eventName)
    CancelEvent()
  end)
end

for _, eventName in ipairs(Config.Firewall.honeypotEvents) do
  RegisterNetEvent(eventName, function()
    Sentinel.Firewall.inspect(source, eventName)
    CancelEvent()
  end)
end

exports('InspectEvent', Sentinel.Firewall.inspect)
