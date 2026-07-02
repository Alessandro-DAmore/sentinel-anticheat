Sentinel = Sentinel or {}
Sentinel.Framework = Sentinel.Framework or {}

function Sentinel.Framework.current()
  return (Config.Framework and Config.Framework.type) or 'standalone'
end
