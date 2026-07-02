Sentinel = Sentinel or {}

function Sentinel.getAdapter()
  local name = Sentinel.Framework.current()
  return (Sentinel.Adapters and Sentinel.Adapters[name]) or Sentinel.Adapters.standalone
end

function Sentinel.isAdmin(source)
  local adapter = Sentinel.getAdapter()
  if adapter and adapter.isAdmin then
    return adapter.isAdmin(source)
  end

  return IsPlayerAceAllowed(source, 'sentinel.admin')
end
