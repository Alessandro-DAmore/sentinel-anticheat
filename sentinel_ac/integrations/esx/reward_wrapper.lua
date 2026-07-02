-- Example for ESX scripts: call this before xPlayer.addMoney/addAccountMoney/addInventoryItem.

local function giveSafeMoney(source, xPlayer, amount, account, context)
  if not exports.sentinel_ac:GuardMoney(source, amount, account, context) then
    return false
  end

  if account == 'bank' or account == 'black_money' then
    xPlayer.addAccountMoney(account, amount)
  else
    xPlayer.addMoney(amount)
  end

  return true
end

local function giveSafeItem(source, xPlayer, item, amount, context)
  if not exports.sentinel_ac:GuardItem(source, item, amount, context) then
    return false
  end

  xPlayer.addInventoryItem(item, amount)
  return true
end

return {
  giveSafeMoney = giveSafeMoney,
  giveSafeItem = giveSafeItem
}
