-- Example for QBCore scripts: call this before Player.Functions.AddMoney/AddItem.

local function giveSafeMoney(source, player, amount, account, context)
  if not exports.sentinel_ac:GuardMoney(source, amount, account, context) then
    return false
  end

  player.Functions.AddMoney(account or 'cash', amount, context or 'sentinel_reward')
  return true
end

local function giveSafeItem(source, player, item, amount, context)
  if not exports.sentinel_ac:GuardItem(source, item, amount, context) then
    return false
  end

  player.Functions.AddItem(item, amount)
  return true
end

return {
  giveSafeMoney = giveSafeMoney,
  giveSafeItem = giveSafeItem
}
