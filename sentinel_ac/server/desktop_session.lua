Sentinel = Sentinel or {}
Sentinel.DesktopSession = Sentinel.DesktopSession or {}

local lastCheck = {}
local joinedAt = {}
local statusBySource = {}
local statusFile = 'data/desktop_session_status.json'

local function writeStatus()
  SaveResourceFile(GetCurrentResourceName(), statusFile, json.encode({
    enabled = Config.DesktopSession.enabled,
    enforce = Config.DesktopSession.enforce,
    checkIntervalMs = Config.DesktopSession.checkIntervalMs,
    players = statusBySource,
    writtenAt = os.time()
  }), -1)
end

print(('[Sentinel AC] desktop session module loaded interval=%sms enforce=%s'):format(
  tostring(Config.DesktopSession.checkIntervalMs),
  tostring(Config.DesktopSession.enforce)
))
writeStatus()

local function discordIdFor(source)
  for _, identifier in ipairs(GetPlayerIdentifiers(source) or {}) do
    local value = identifier:match('^discord:(.+)$')
    if value and value ~= '' then
      return value
    end
  end

  return nil
end

local function desktopSessionMessage(reason)
  if reason == 'desktop_anticheat_not_active' or reason == 'session_not_found' or reason == 'desktop_anticheat_heartbeat_expired' then
    return Config.DesktopSession.notActiveMessage or Config.DesktopSession.kickMessage
  end

  if reason == 'suspicious_scan_blocked' or reason == 'suspicious_scan_ban' or reason == 'runtime_suspicious_process' then
    return Config.DesktopSession.suspiciousKickMessage or Config.DesktopSession.kickMessage
  end

  return Config.DesktopSession.kickMessage
end

local function canGraceInactive(source, reason)
  if reason ~= 'desktop_anticheat_not_active' and reason ~= 'session_not_found' and reason ~= 'desktop_anticheat_heartbeat_expired' then
    return false
  end

  local startedAt = joinedAt[source]
  if not startedAt then
    return false
  end

  local graceMs = tonumber(Config.DesktopSession.startupGraceMs or 0) or 0
  return graceMs > 0 and Sentinel.nowMs() - startedAt <= graceMs
end

local function kickForDesktopSession(source, reason)
  statusBySource[source] = {
    ok = false,
    reason = reason,
    checkedAt = os.time()
  }
  writeStatus()

  if not Config.DesktopSession.enforce then
    print(('[Sentinel AC] monitor desktop session: would kick %s reason=%s'):format(source, reason))
    return
  end

  DropPlayer(source, desktopSessionMessage(reason))
end

function Sentinel.DesktopSession.check(source)
  if not Config.DesktopSession.enabled then
    return
  end

  if not Config.Cloud.enabled then
    if Config.Cloud.failMode == 'block' then
      kickForDesktopSession(source, 'cloud disabled')
    end
    return
  end

  local discordId = discordIdFor(source)
  if not discordId then
    if Config.DesktopSession.requireDiscordIdentifier then
      statusBySource[source] = {
        ok = false,
        reason = 'missing_discord_identifier',
        checkedAt = os.time()
      }
      writeStatus()

      if Config.DesktopSession.enforce then
        DropPlayer(source, Config.DesktopSession.missingDiscordMessage)
      else
        print(('[Sentinel AC] monitor desktop session: player %s has no discord identifier'):format(source))
      end
    end
    return
  end

  Sentinel.Cloud.request('/v1/server/session/check', {
    discordId = discordId,
    playerName = Sentinel.safePlayerName(source),
    playerEndpoint = GetPlayerEndpoint(source)
  }, function(ok, response, errorMessage)
    if not ok then
      if Config.Cloud.failMode == 'block' then
        kickForDesktopSession(source, errorMessage or 'cloud unavailable')
      else
        print(('[Sentinel AC] desktop session cloud check failed for %s: %s'):format(source, tostring(errorMessage)))
      end
      return
    end

    if response and response.banned then
      statusBySource[source] = {
        ok = false,
        discordId = discordId,
        reason = tostring(response.reason or 'banned'),
        checkedAt = os.time()
      }
      writeStatus()

      if Config.DesktopSession.enforce then
        DropPlayer(source, 'Sentinel AC ban: ' .. tostring(response.reason or 'banned'))
      else
        print(('[Sentinel AC] monitor desktop session: would ban/kick %s reason=%s'):format(source, tostring(response.reason)))
      end
      return
    end

    if not response or response.active ~= true then
      local reason = response and response.reason or 'desktop_anticheat_not_active'
      if canGraceInactive(source, reason) then
        statusBySource[source] = {
          ok = false,
          pending = true,
          discordId = discordId,
          reason = reason,
          graceUntilMs = (joinedAt[source] or Sentinel.nowMs()) + (tonumber(Config.DesktopSession.startupGraceMs or 0) or 0),
          checkedAt = os.time()
        }
        writeStatus()
        print(('[Sentinel AC] desktop session pending for %s reason=%s'):format(source, tostring(reason)))
        return
      end

      kickForDesktopSession(source, reason)
      return
    end

    joinedAt[source] = nil
    statusBySource[source] = {
      ok = true,
      discordId = discordId,
      sessionId = response.sessionId,
      checkedAt = os.time()
    }
    writeStatus()
  end)
end

AddEventHandler('playerDropped', function()
  lastCheck[source] = nil
  joinedAt[source] = nil
  statusBySource[source] = nil
  writeStatus()
end)

AddEventHandler('playerConnecting', function()
  local player = source
  joinedAt[player] = joinedAt[player] or Sentinel.nowMs()
  SetTimeout(8000, function()
    if GetPlayerName(player) then
      Sentinel.DesktopSession.check(player)
    else
      statusBySource[player] = {
        ok = false,
        reason = 'player_not_ready_after_connecting',
        checkedAt = os.time()
      }
      writeStatus()
    end
  end)
end)

AddEventHandler('playerJoining', function()
  local player = source
  joinedAt[player] = joinedAt[player] or Sentinel.nowMs()
  SetTimeout(5000, function()
    if GetPlayerName(player) then
      Sentinel.DesktopSession.check(player)
    end
  end)
end)

CreateThread(function()
  while true do
    Wait(Config.DesktopSession.checkIntervalMs)

    if Config.DesktopSession.enabled then
      local now = Sentinel.nowMs()
      for _, player in ipairs(GetPlayers()) do
        local source = tonumber(player)
        if source then
          local previous = lastCheck[source] or 0
          if now - previous >= Config.DesktopSession.checkIntervalMs then
            lastCheck[source] = now
            Sentinel.DesktopSession.check(source)
          end
        end
      end
    end
  end
end)

RegisterCommand('sentinel_session_check', function(source, args)
  if source ~= 0 and not Sentinel.isAdmin(source) then
    return
  end

  local target = tonumber(args[1] or source)
  if not target or target <= 0 then
    print('[Sentinel AC] usage: sentinel_session_check <playerId>')
    return
  end

  Sentinel.DesktopSession.check(target)
  print(('[Sentinel AC] desktop session requested for player=%s discord=%s status=%s'):format(
    target,
    tostring(discordIdFor(target) or 'missing'),
    json.encode(statusBySource[target] or {})
  ))
end, true)
