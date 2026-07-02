Sentinel = Sentinel or {}
Sentinel.Adapters = Sentinel.Adapters or {}

Sentinel.Adapters.vrp = {
  name = 'vrp',
  isAdmin = function(source)
    return IsPlayerAceAllowed(source, 'sentinel.admin')
  end
}
