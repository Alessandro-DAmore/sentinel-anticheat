Sentinel = Sentinel or {}
Sentinel.Entities = Sentinel.Entities or {}

local entityWindows = {}

local function modelName(entity)
  local model = GetEntityModel(entity)
  return tostring(model)
end

local function bump(source)
  local now = Sentinel.nowMs()
  local bucket = entityWindows[source] or { startedAt = now, count = 0 }

  if now - bucket.startedAt > Config.Entities.windowMs then
    bucket.startedAt = now
    bucket.count = 0
  end

  bucket.count = bucket.count + 1
  entityWindows[source] = bucket
  return bucket.count
end

AddEventHandler('entityCreating', function(entity)
  if not Config.Modules.entityProtection then
    return
  end

  local owner = NetworkGetEntityOwner(entity)
  if not owner or owner == 0 then
    return
  end

  if bump(owner) > Config.Entities.maxCreatedPerWindow then
    CancelEvent()
    Sentinel.Punishments.apply(owner, 'entity_spam', modelName(entity))
  end
end)

AddEventHandler('explosionEvent', function(source)
  if Config.Modules.entityProtection and Config.Entities.blockExplosions then
    CancelEvent()
    Sentinel.Punishments.apply(source, 'explosion_spam', 'explosion event')
  end
end)
