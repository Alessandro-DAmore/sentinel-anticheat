Config = {}

-- Server-only configuration. Do not move this file into shared_scripts:
-- it contains privacy secrets, license keys, webhook URLs, and cloud keys.
Config.Product = {
  name = 'Sentinel AC',
  mode = 'monitor', -- monitor, enforce
  locale = 'it'
}

Config.Framework = {
  type = 'standalone', -- standalone, esx, qbcore, vrp
  resourceName = nil
}

Config.Privacy = {
  -- Change this before production. Keep it out of screenshots and support tickets.
  serverSecret = 'CHANGE_ME_LONG_RANDOM_SECRET',
  hashIdentifiers = true,
  redactDiscordLogs = true,
  keepRawIdentifiersInMemoryOnly = true
}

Config.Webhooks = {
  enabled = false,
  url = '',
  username = 'Sentinel AC',
  avatarUrl = ''
}

Config.Cloud = {
  enabled = true,
  endpoint = 'http://127.0.0.1:8787',
  licenseKey = 'CHANGE_ME_SENTINEL_LICENSE',
  serverKey = 'CHANGE_ME_SENTINEL_SERVER_KEY',
  sharedSecret = 'CHANGE_ME_SENTINEL_SHARED_SECRET',
  timeoutMs = 5000,
  failMode = 'monitor', -- monitor, block
  verifyIntervalMs = 300000,
  sendTelemetry = true,
  requireSignedDecisions = true
}

Config.DesktopSession = {
  enabled = true,
  enforce = true,
  checkIntervalMs = 5000,
  requireDiscordIdentifier = true,
  kickMessage = "Hai chiuso l'app del Sentinel Anticheat, ti ricordiamo che devi tenerla aperta per poter giocare.",
  suspiciousKickMessage = 'Sentinel AC: file sospetto rilevato. Passa in "Attesa Anticheat" sul Discord del server.',
  missingDiscordMessage = 'Sentinel AC: devi collegare Discord prima di entrare nel server.'
}

Config.Modules = {
  eventFirewall = true,
  entityProtection = true,
  movementChecks = true,
  heartbeat = true,
  weaponGuard = true,
  vehicleGuard = true,
  economyGuard = true,
  frameworkGuard = true,
  adminProtection = true
}

Config.Punishments = {
  default = 'log', -- log, warn, kick, ban
  event_spam = 'kick',
  blocked_event = 'kick',
  entity_spam = 'kick',
  explosion_spam = 'ban',
  suspicious_teleport = 'warn',
  speedhack = 'warn',
  godmode = 'warn',
  blacklisted_weapon = 'kick',
  blacklisted_vehicle = 'kick',
  heartbeat_lost = 'kick',
  money_exploit = 'kick',
  item_exploit = 'kick',
  job_exploit = 'warn',
  protected_event_abuse = 'kick',
  admin_abuse = 'ban'
}

Config.Firewall = {
  maxEventsPerWindow = 35,
  windowMs = 3000,
  blockedEvents = {
    'esx:getSharedObject',
    'HCheat:TempDisableDetection',
    'redst0nia:checking',
    'antilynx8:anticheat',
    'antilynxr4:detect',
    'ynx8:anticheat'
  },
  honeypotEvents = {
    'sentinel:giveMoney',
    'sentinel:adminBypass',
    'sentinel:spawnVehicle'
  }
}

Config.Entities = {
  maxCreatedPerWindow = 18,
  windowMs = 5000,
  blockExplosions = true,
  blacklistedModels = {
    'rhino',
    'hydra',
    'lazer',
    'cargoplane'
  }
}

Config.Movement = {
  checkIntervalMs = 5000,
  maxOnFootSpeed = 13.0,
  maxVehicleSpeed = 105.0,
  maxTeleportDistance = 220.0,
  ignoreAdminGroups = true
}

Config.Heartbeat = {
  intervalMs = 10000,
  timeoutMs = 35000
}

Config.Weapons = {
  blacklisted = {
    'WEAPON_RAILGUN',
    'WEAPON_RPG',
    'WEAPON_MINIGUN',
    'WEAPON_GRENADELAUNCHER'
  }
}

Config.Economy = {
  maxCashReward = 25000,
  maxBankReward = 100000,
  maxItemAmount = 50,
  maxWarningsBeforeKick = 3,
  eventWindowMs = 10000,
  maxMoneyEventsPerWindow = 6,
  maxCashRewardWindow = 60000,
  maxBankRewardWindow = 180000,
  maxItemEventsPerWindow = 8,
  maxItemAmountPerWindow = 120,
  accountSnapshotIntervalMs = 15000,
  maxCashDeltaPerInterval = 75000,
  maxBankDeltaPerInterval = 200000,
  maxInventoryDeltaPerInterval = 75,
  monitorNegativeMoney = true,
  protectedEvents = {
    -- Example:
    -- {
    --   name = 'my_job:server:giveReward',
    --   type = 'money',
    --   amountArg = 1,
    --   maxAmount = 15000
    -- }
  },
  blacklistedItems = {
    'weapon_rpg',
    'weapon_minigun',
    'black_money'
  },
  protectedJobs = {
    'police',
    'ambulance',
    'mechanic'
  }
}

Config.FrameworkGuards = {
  esx = {
    enabled = true,
    accountNames = {
      cash = 'money',
      bank = 'bank',
      black = 'black_money'
    }
  },
  qbcore = {
    enabled = true,
    accountNames = {
      cash = 'cash',
      bank = 'bank',
      crypto = 'crypto'
    }
  }
}

Config.AdminGuard = {
  requiredAce = 'sentinel.admin',
  protectedActions = {
    'give_money',
    'give_item',
    'set_job',
    'revive',
    'heal',
    'spawn_vehicle',
    'noclip',
    'teleport'
  }
}
