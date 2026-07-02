Sentinel = Sentinel or {}
Sentinel.Privacy = Sentinel.Privacy or {}

local function stableHash(input, seed)
  local hash = seed or 5381

  for index = 1, #input do
    hash = ((hash * 33) + string.byte(input, index)) % 4294967296
  end

  return string.format('%08x', hash)
end

local function layeredHash(input)
  local secret = Config.Privacy.serverSecret or ''
  local mixed = ('%s:%s:%s'):format(secret, input or '', GetConvar('sv_hostname', 'server'))

  return table.concat({
    stableHash(mixed, 5381),
    stableHash(string.reverse(mixed), 52711),
    stableHash(mixed .. ':sentinel', 1315423911),
    stableHash('sentinel:' .. mixed, 2654435761)
  })
end

function Sentinel.Privacy.fingerprint(value)
  if not value or value == '' then
    return 'unknown'
  end

  return layeredHash(tostring(value))
end

function Sentinel.Privacy.redact(value)
  if not value or value == '' then
    return 'unknown'
  end

  local text = tostring(value)
  if #text <= 8 then
    return 'redacted:' .. Sentinel.Privacy.fingerprint(text):sub(1, 12)
  end

  return text:sub(1, 4) .. '...' .. Sentinel.Privacy.fingerprint(text):sub(1, 12)
end

function Sentinel.Privacy.playerRecord(source)
  local identifiers = GetPlayerIdentifiers(source) or {}
  local record = {
    source = source,
    name = Sentinel.safePlayerName(source),
    fingerprint = 'unknown',
    identifiers = {}
  }

  for _, identifier in ipairs(identifiers) do
    local key = identifier:match('^([^:]+):') or 'identifier'
    local hashed = Sentinel.Privacy.fingerprint(identifier)
    record.identifiers[key] = hashed

    if record.fingerprint == 'unknown' and (key == 'license' or key == 'fivem') then
      record.fingerprint = hashed
    end
  end

  if record.fingerprint == 'unknown' and identifiers[1] then
    record.fingerprint = Sentinel.Privacy.fingerprint(identifiers[1])
  end

  return record
end

function Sentinel.Privacy.publicPlayerRecord(source)
  local record = Sentinel.Privacy.playerRecord(source)

  if Config.Privacy.redactDiscordLogs then
    record.name = Sentinel.Privacy.redact(record.name)
  end

  return record
end
