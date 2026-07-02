Sentinel = Sentinel or {}
Sentinel.AdminGuard = Sentinel.AdminGuard or {}

function Sentinel.AdminGuard.authorize(source, action, context)
  if not Config.Modules.adminProtection then
    return true
  end

  action = tostring(action or '')

  if not Sentinel.tableHasValue(Config.AdminGuard.protectedActions, action) then
    return true
  end

  if Sentinel.isAdmin(source) or IsPlayerAceAllowed(source, Config.AdminGuard.requiredAce) then
    return true
  end

  Sentinel.Punishments.apply(source, 'admin_abuse', (context or 'admin_guard') .. ':' .. action)
  return false
end

RegisterNetEvent('sentinel:adminAction', function(action, context)
  Sentinel.AdminGuard.authorize(source, action, context)
end)

exports('AuthorizeAdminAction', Sentinel.AdminGuard.authorize)
