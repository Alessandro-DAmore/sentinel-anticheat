Sentinel = Sentinel or {}
Sentinel.Webhooks = Sentinel.Webhooks or {}

function Sentinel.Webhooks.send(title, fields, color)
  if not Config.Webhooks.enabled or Config.Webhooks.url == '' then
    return
  end

  local embedFields = {}
  for key, value in pairs(fields or {}) do
    embedFields[#embedFields + 1] = {
      name = tostring(key),
      value = tostring(value),
      inline = false
    }
  end

  local payload = {
    username = Config.Webhooks.username,
    avatar_url = Config.Webhooks.avatarUrl,
    embeds = {{
      title = title,
      color = color or 16753920,
      fields = embedFields,
      footer = { text = 'Sentinel AC privacy-safe telemetry' },
      timestamp = os.date('!%Y-%m-%dT%H:%M:%SZ')
    }}
  }

  PerformHttpRequest(Config.Webhooks.url, function() end, 'POST', json.encode(payload), {
    ['Content-Type'] = 'application/json'
  })
end
