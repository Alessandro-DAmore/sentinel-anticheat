Config = Config or {}

-- Client-safe settings only. Keep secrets, webhooks, license keys, and privacy
-- keys in config.lua, which is loaded server-side only.
Config.Modules = {
  movementChecks = true,
  heartbeat = true,
  weaponGuard = true,
  vehicleGuard = true
}

Config.Movement = {
  checkIntervalMs = 5000
}

Config.Heartbeat = {
  intervalMs = 10000
}

Config.Weapons = {
  blacklisted = {
    'WEAPON_RAILGUN',
    'WEAPON_RPG',
    'WEAPON_MINIGUN',
    'WEAPON_GRENADELAUNCHER'
  }
}

Config.Entities = {
  blacklistedModels = {
    'rhino',
    'hydra',
    'lazer',
    'cargoplane'
  }
}
