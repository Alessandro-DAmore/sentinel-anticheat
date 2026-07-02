Sentinel = Sentinel or {}
Sentinel.Telemetry = Sentinel.Telemetry or {}

local queue = {}

local function severityFor(code)
  local severities = {
    event_spam = 70,
    blocked_event = 85,
    entity_spam = 75,
    explosion_spam = 95,
    suspicious_teleport = 45,
    speedhack = 55,
    godmode = 65,
    blacklisted_weapon = 80,
    blacklisted_vehicle = 80,
    heartbeat_lost = 40,
    money_exploit = 85,
    item_exploit = 80,
    job_exploit = 60,
    protected_event_abuse = 88,
    admin_abuse = 95
  }

  return severities[code] or 30
end

function Sentinel.Telemetry.report(source, code, detail, localAction, callback)
  if not Config.Cloud.enabled or not Config.Cloud.sendTelemetry then
    if callback then callback(nil) end
    return
  end

  local player = Sentinel.Privacy.publicPlayerRecord(source)
  local event = {
    playerFingerprint = player.fingerprint,
    detection = code,
    detailHash = Sentinel.Privacy.fingerprint(detail or code),
    severity = severityFor(code),
    localAction = localAction,
    framework = Sentinel.Framework.current(),
    resource = GetCurrentResourceName()
  }

  queue[#queue + 1] = event

  Sentinel.Cloud.request('/v1/detection/report', event, function(ok, response)
    if not ok or type(response) ~= 'table' then
      if callback then callback(nil) end
      return
    end

    if response.decision and Sentinel.Cloud.verifyDecision(response.decision) then
      if callback then callback(response.decision) end
      return
    end

    if callback then callback(nil) end
  end)
end

function Sentinel.Telemetry.queued()
  return Sentinel.copyTable(queue)
end
