Sentinel = Sentinel or {}
Sentinel.Bans = Sentinel.Bans or {}

function Sentinel.Bans.ban(source, reason)
  local player = Sentinel.Privacy.playerRecord(source)
  Sentinel.Storage.addBan(player.fingerprint, {
    reason = reason,
    identifiers = player.identifiers,
    createdAt = os.time()
  })

  DropPlayer(source, 'Sentinel AC ban: ' .. reason)
end

AddEventHandler('playerConnecting', function(_, setKickReason, deferrals)
  local source = source

  local ok, blocked, reason = pcall(function()
    local player = Sentinel.Privacy.playerRecord(source)
    local ban = Sentinel.Storage.getBan(player.fingerprint)

    if ban then
      return true, 'Sentinel AC: access denied.'
    end

    return false, nil
  end)

  if not ok then
    print('[Sentinel AC] playerConnecting check failed: ' .. tostring(blocked))
    return
  end

  if blocked then
    setKickReason(reason or 'Sentinel AC: access denied.')
    CancelEvent()
    return
  end
end)
