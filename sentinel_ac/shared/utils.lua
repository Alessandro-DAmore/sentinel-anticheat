Sentinel = Sentinel or {}

function Sentinel.nowMs()
  return GetGameTimer()
end

function Sentinel.tableHasValue(values, candidate)
  for _, value in ipairs(values or {}) do
    if value == candidate then
      return true
    end
  end

  return false
end

function Sentinel.copyTable(input)
  local output = {}

  for key, value in pairs(input or {}) do
    if type(value) == 'table' then
      output[key] = Sentinel.copyTable(value)
    else
      output[key] = value
    end
  end

  return output
end

function Sentinel.safePlayerName(source)
  local name = GetPlayerName(source)
  if not name or name == '' then
    return ('player:%s'):format(source)
  end

  return name
end

function Sentinel.reasonText(code, detail)
  if detail and detail ~= '' then
    return ('%s: %s'):format(code, detail)
  end

  return code
end
