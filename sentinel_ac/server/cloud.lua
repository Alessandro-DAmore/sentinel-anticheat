Sentinel = Sentinel or {}
Sentinel.Cloud = Sentinel.Cloud or {}

local function buildUrl(path)
  local endpoint = Config.Cloud.endpoint or ''
  return endpoint:gsub('/$', '') .. path
end

local function stableHash(input, seed)
  local hash = seed or 5381

  for index = 1, #input do
    hash = ((hash * 33) + string.byte(input, index)) % 4294967296
  end

  return string.format('%08x', hash)
end

local function cloudFingerprint(value)
  local input = tostring(value or '')

  return table.concat({
    stableHash(input, 5381),
    stableHash(string.reverse(input), 52711),
    stableHash(input .. ':sentinel', 1315423911),
    stableHash('sentinel:' .. input, 2654435761)
  })
end

local function signatureFor(body)
  local secret = Config.Cloud.sharedSecret or ''
  return cloudFingerprint(secret .. ':' .. body)
end

local function decisionSignature(decision)
  local secret = Config.Cloud.sharedSecret or ''
  local canonical = table.concat({
    tostring(decision.action or ''),
    tostring(decision.reason or ''),
    tostring(decision.confidence or ''),
    tostring(decision.nonce or '')
  }, '|')

  return cloudFingerprint(secret .. ':decision:' .. canonical)
end

function Sentinel.Cloud.serverId()
  local hostname = GetConvar('sv_hostname', 'server')
  local endpointPrivacy = GetConvar('sv_endpointprivacy', 'unknown')
  return Sentinel.Privacy.fingerprint(hostname .. ':' .. endpointPrivacy)
end

function Sentinel.Cloud.request(path, payload, callback)
  if not Config.Cloud.enabled then
    callback(false, nil, 'cloud_disabled')
    return
  end

  payload = payload or {}
  payload.licenseKey = Config.Cloud.licenseKey
  payload.serverId = Sentinel.Cloud.serverId()
  payload.sentAt = os.time()

  local body = json.encode(payload)
  local headers = {
    ['Content-Type'] = 'application/json',
    ['X-Sentinel-Key'] = Config.Cloud.serverKey,
    ['X-Sentinel-Signature'] = signatureFor(body)
  }

  PerformHttpRequest(buildUrl(path), function(status, response)
    if status < 200 or status >= 300 then
      callback(false, nil, 'http_' .. tostring(status))
      return
    end

    local ok, decoded = pcall(json.decode, response or '{}')
    if not ok then
      callback(false, nil, 'invalid_json')
      return
    end

    callback(true, decoded, nil)
  end, 'POST', body, headers)
end

function Sentinel.Cloud.verifyDecision(decision)
  if not Config.Cloud.requireSignedDecisions then
    return true
  end

  if type(decision) ~= 'table' or not decision.signature then
    return false
  end

  local expected = decisionSignature(decision)
  return expected == decision.signature
end
