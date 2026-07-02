Sentinel = Sentinel or {}
Sentinel.FrameworkGuards = Sentinel.FrameworkGuards or {}

local snapshots = {}

local function shouldRun()
  if not Config.Modules.frameworkGuard or not Config.Modules.economyGuard then
    return false
  end

  local framework = Sentinel.Framework.current()
  local frameworkConfig = Config.FrameworkGuards[framework]
  return frameworkConfig and frameworkConfig.enabled
end

local function accountDelta(previous, current, key)
  if not previous or not current then
    return 0
  end

  return (tonumber(current[key] or 0) or 0) - (tonumber(previous[key] or 0) or 0)
end

local function inspectMoney(source, previous, current)
  if Config.Economy.monitorNegativeMoney then
    if (current.cash or 0) < 0 or (current.bank or 0) < 0 then
      Sentinel.Punishments.apply(source, 'money_exploit', 'negative account balance')
      return
    end
  end

  local cashDelta = accountDelta(previous, current, 'cash')
  local bankDelta = accountDelta(previous, current, 'bank')

  if cashDelta > Config.Economy.maxCashDeltaPerInterval then
    Sentinel.Punishments.apply(source, 'money_exploit', ('cash delta=%s'):format(cashDelta))
  end

  if bankDelta > Config.Economy.maxBankDeltaPerInterval then
    Sentinel.Punishments.apply(source, 'money_exploit', ('bank delta=%s'):format(bankDelta))
  end
end

local function inspectJob(source, previous, current)
  if not previous or not current or not previous.job or not current.job then
    return
  end

  if previous.job ~= current.job and Sentinel.tableHasValue(Config.Economy.protectedJobs, current.job) and not Sentinel.isAdmin(source) then
    Sentinel.Punishments.apply(source, 'job_exploit', ('job changed %s -> %s'):format(previous.job, current.job))
  end
end

function Sentinel.FrameworkGuards.snapshot(source)
  local adapter = Sentinel.getAdapter()
  if not adapter or not adapter.snapshot then
    return nil
  end

  return adapter.snapshot(source)
end

CreateThread(function()
  while true do
    Wait(Config.Economy.accountSnapshotIntervalMs)

    if shouldRun() then
      for _, player in ipairs(GetPlayers()) do
        local source = tonumber(player)
        local current = Sentinel.FrameworkGuards.snapshot(source)

        if current then
          local previous = snapshots[source]
          inspectMoney(source, previous, current)
          inspectJob(source, previous, current)
          snapshots[source] = current
        end
      end
    end
  end
end)

AddEventHandler('playerDropped', function()
  snapshots[source] = nil
end)
