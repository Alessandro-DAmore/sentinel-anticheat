Sentinel = Sentinel or {}
Sentinel.Economy = Sentinel.Economy or {}

local strikes = {}
local economyWindows = {}

local function strike(source, code, detail)
  local player = Sentinel.Privacy.publicPlayerRecord(source)
  strikes[player.fingerprint] = (strikes[player.fingerprint] or 0) + 1

  Sentinel.Punishments.apply(source, code, detail)

  if strikes[player.fingerprint] >= Config.Economy.maxWarningsBeforeKick then
    Sentinel.Punishments.apply(source, 'protected_event_abuse', 'repeated economy guard strikes')
  end
end

local function numericAmount(value)
  local amount = tonumber(value)
  if not amount then
    return nil
  end

  return amount
end

local function windowKey(source, kind, subject)
  local player = Sentinel.Privacy.publicPlayerRecord(source)
  return ('%s:%s:%s'):format(player.fingerprint, kind, tostring(subject or 'default'):lower())
end

local function bumpWindow(source, kind, subject, amount)
  local key = windowKey(source, kind, subject)
  local now = Sentinel.nowMs()
  local windowMs = Config.Economy.eventWindowMs or 10000
  local bucket = economyWindows[key]

  if not bucket or now - bucket.startedAt > windowMs then
    bucket = {
      startedAt = now,
      count = 0,
      total = 0
    }
    economyWindows[key] = bucket
  end

  bucket.count = bucket.count + 1
  bucket.total = bucket.total + tonumber(amount or 0)
  return bucket
end

function Sentinel.Economy.guardMoney(source, amount, account, context)
  if not Config.Modules.economyGuard then
    return true
  end

  amount = numericAmount(amount)
  account = account or 'cash'

  if not amount or amount <= 0 then
    strike(source, 'money_exploit', (context or 'money') .. ': invalid amount')
    return false
  end

  local limit = account == 'bank' and Config.Economy.maxBankReward or Config.Economy.maxCashReward
  if amount > limit then
    strike(source, 'money_exploit', ('%s amount=%s limit=%s'):format(context or account, amount, limit))
    return false
  end

  local bucket = bumpWindow(source, 'money', account, amount)
  local maxEvents = Config.Economy.maxMoneyEventsPerWindow or 6
  local maxWindow = account == 'bank' and Config.Economy.maxBankRewardWindow or Config.Economy.maxCashRewardWindow
  if bucket.count > maxEvents or bucket.total > maxWindow then
    strike(source, 'money_exploit', ('%s account=%s window_count=%s window_total=%s'):format(context or 'money_window', account, bucket.count, bucket.total))
    return false
  end

  return true
end

function Sentinel.Economy.guardItem(source, itemName, amount, context)
  if not Config.Modules.economyGuard then
    return true
  end

  amount = numericAmount(amount or 1)
  itemName = tostring(itemName or ''):lower()

  if itemName == '' or not amount or amount <= 0 then
    strike(source, 'item_exploit', (context or 'item') .. ': invalid item payload')
    return false
  end

  if Sentinel.tableHasValue(Config.Economy.blacklistedItems, itemName) then
    strike(source, 'item_exploit', ('%s blacklisted=%s'):format(context or 'item', itemName))
    return false
  end

  if amount > Config.Economy.maxItemAmount then
    strike(source, 'item_exploit', ('%s item=%s amount=%s'):format(context or 'item', itemName, amount))
    return false
  end

  local bucket = bumpWindow(source, 'item', itemName, amount)
  if bucket.count > (Config.Economy.maxItemEventsPerWindow or 8) or bucket.total > (Config.Economy.maxItemAmountPerWindow or 120) then
    strike(source, 'item_exploit', ('%s item=%s window_count=%s window_total=%s'):format(context or 'item_window', itemName, bucket.count, bucket.total))
    return false
  end

  return true
end

function Sentinel.Economy.guardJob(source, jobName, context)
  if not Config.Modules.economyGuard then
    return true
  end

  jobName = tostring(jobName or ''):lower()

  if Sentinel.tableHasValue(Config.Economy.protectedJobs, jobName) and not Sentinel.isAdmin(source) then
    strike(source, 'job_exploit', ('%s job=%s'):format(context or 'job', jobName))
    return false
  end

  return true
end

local function inspectProtectedEvent(definition, eventSource, args)
  if type(definition) ~= 'table' then
    return
  end

  if definition.type == 'money' then
    local amount = args[definition.amountArg or 1]
    local account = definition.account or args[definition.accountArg or -1] or 'cash'
    local maxAmount = definition.maxAmount

    if maxAmount and tonumber(amount) and tonumber(amount) > tonumber(maxAmount) then
      strike(eventSource, 'money_exploit', definition.name .. ': protected event limit')
      CancelEvent()
      return
    end

    if not Sentinel.Economy.guardMoney(eventSource, amount, account, definition.name) then
      CancelEvent()
    end
    return
  end

  if definition.type == 'item' then
    local item = args[definition.itemArg or 1]
    local amount = args[definition.amountArg or 2] or 1

    if not Sentinel.Economy.guardItem(eventSource, item, amount, definition.name) then
      CancelEvent()
    end
    return
  end

  if definition.type == 'job' then
    local job = args[definition.jobArg or 1]

    if not Sentinel.Economy.guardJob(eventSource, job, definition.name) then
      CancelEvent()
    end
  end
end

for _, definition in ipairs(Config.Economy.protectedEvents or {}) do
  if definition.name then
    RegisterNetEvent(definition.name, function(...)
      inspectProtectedEvent(definition, source, { ... })
    end)
  end
end

AddEventHandler('playerDropped', function()
  local player = Sentinel.Privacy.publicPlayerRecord(source)
  local prefix = player.fingerprint .. ':'
  for key in pairs(economyWindows) do
    if key:sub(1, #prefix) == prefix then
      economyWindows[key] = nil
    end
  end
  strikes[player.fingerprint] = nil
end)

exports('GuardMoney', Sentinel.Economy.guardMoney)
exports('GuardItem', Sentinel.Economy.guardItem)
exports('GuardJob', Sentinel.Economy.guardJob)
