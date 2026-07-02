Sentinel = Sentinel or {}
Sentinel.Preflight = Sentinel.Preflight or {}

local warnings = {}
local failures = {}

local function addWarning(message)
  warnings[#warnings + 1] = message
end

local function addFailure(message)
  failures[#failures + 1] = message
end

local function isPlaceholder(value)
  value = tostring(value or '')
  return value == '' or value:find('CHANGE_ME', 1, true) or value:find('replace_me', 1, true)
end

local function validFramework()
  local framework = Sentinel.Framework.current()
  return framework == 'standalone' or framework == 'esx' or framework == 'qbcore' or framework == 'vrp'
end

local function checkPrivacy()
  if isPlaceholder(Config.Privacy.serverSecret) then
    addWarning('Config.Privacy.serverSecret is still a development placeholder.')
  end

  if Config.Privacy.redactDiscordLogs ~= true then
    addWarning('Config.Privacy.redactDiscordLogs should stay true for privacy-safe support logs.')
  end
end

local function checkCloud()
  if not Config.Cloud.enabled then
    addWarning('Cloud is disabled. License checks and remote signed decisions are not active.')
    return
  end

  if isPlaceholder(Config.Cloud.licenseKey) then
    addFailure('Config.Cloud.licenseKey must be set before cloud mode.')
  end

  if isPlaceholder(Config.Cloud.serverKey) then
    addFailure('Config.Cloud.serverKey must be set before cloud mode.')
  end

  if isPlaceholder(Config.Cloud.sharedSecret) then
    addFailure('Config.Cloud.sharedSecret must be set before cloud mode.')
  end

  if not Config.Cloud.endpoint or Config.Cloud.endpoint == '' then
    addFailure('Config.Cloud.endpoint is empty.')
  end
end

local function checkFramework()
  if not validFramework() then
    addFailure('Config.Framework.type must be standalone, esx, qbcore, or vrp.')
  end

  local framework = Sentinel.Framework.current()
  if framework == 'esx' and GetResourceState(Config.Framework.resourceName or 'es_extended') == 'missing' then
    addWarning('ESX resource was not found at startup. Set Config.Framework.resourceName if it has a custom name.')
  end

  if framework == 'qbcore' and GetResourceState(Config.Framework.resourceName or 'qb-core') == 'missing' then
    addWarning('QBCore resource was not found at startup. Set Config.Framework.resourceName if it has a custom name.')
  end
end

local function checkMode()
  if Config.Product.mode ~= 'monitor' and Config.Product.mode ~= 'enforce' then
    addFailure('Config.Product.mode must be monitor or enforce.')
  end

  if Config.Product.mode == 'enforce' and isPlaceholder(Config.Privacy.serverSecret) then
    addFailure('Do not use enforce mode with the default privacy secret.')
  end
end

local function checkEconomy()
  if Config.Modules.economyGuard and #(Config.Economy.protectedEvents or {}) == 0 then
    addWarning('No Config.Economy.protectedEvents configured. Add direct exports to reward/shop/admin scripts before production.')
  end

  if Config.Economy.maxCashReward <= 0 or Config.Economy.maxBankReward <= 0 then
    addFailure('Economy reward limits must be greater than zero.')
  end
end

function Sentinel.Preflight.run()
  warnings = {}
  failures = {}

  checkMode()
  checkPrivacy()
  checkCloud()
  checkFramework()
  checkEconomy()

  for _, message in ipairs(warnings) do
    print('[Sentinel AC] preflight warning: ' .. message)
  end

  for _, message in ipairs(failures) do
    print('[Sentinel AC] preflight failure: ' .. message)
  end

  if #failures > 0 then
    print('[Sentinel AC] preflight result: failed. Resource will stay loaded, but production enforcement is unsafe.')
    return false
  end

  print(('[Sentinel AC] preflight result: ok (%s warning%s)'):format(
    #warnings,
    #warnings == 1 and '' or 's'
  ))
  return true
end

function Sentinel.Preflight.summary()
  return {
    warnings = Sentinel.copyTable(warnings),
    failures = Sentinel.copyTable(failures)
  }
end
