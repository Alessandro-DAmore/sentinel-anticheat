Sentinel = Sentinel or {}
Sentinel.Adapters = Sentinel.Adapters or {}

Sentinel.Adapters.standalone = {
  name = 'standalone',
  isAdmin = function(source)
    return IsPlayerAceAllowed(source, 'sentinel.admin')
  end,
  getMoney = function()
    return nil
  end,
  getJob = function()
    return nil
  end
}
