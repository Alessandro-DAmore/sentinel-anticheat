Sentinel = Sentinel or {}
Sentinel.Storage = Sentinel.Storage or {}

local bans = {}
local warnings = {}
local bansFile = 'data/bans.json'

local function loadBans()
  local raw = LoadResourceFile(GetCurrentResourceName(), bansFile)
  if not raw or raw == '' then
    bans = {}
    return
  end

  local ok, decoded = pcall(json.decode, raw)
  bans = (ok and type(decoded) == 'table') and decoded or {}
end

local function saveBans()
  SaveResourceFile(GetCurrentResourceName(), bansFile, json.encode(bans), -1)
end

loadBans()

function Sentinel.Storage.addBan(fingerprint, ban)
  bans[fingerprint] = ban
  saveBans()
end

function Sentinel.Storage.getBan(fingerprint)
  return bans[fingerprint]
end

function Sentinel.Storage.removeBan(fingerprint)
  bans[fingerprint] = nil
  saveBans()
end

function Sentinel.Storage.addWarning(fingerprint, warning)
  warnings[fingerprint] = warnings[fingerprint] or {}
  warnings[fingerprint][#warnings[fingerprint] + 1] = warning
end

function Sentinel.Storage.warningCount(fingerprint)
  return #(warnings[fingerprint] or {})
end

function Sentinel.Storage.allBans()
  return Sentinel.copyTable(bans)
end
