fx_version 'cerulean'
game 'gta5'

name 'Sentinel AC'
author 'Sentinel Security'
description 'Modular privacy-first anticheat for FiveM roleplay servers.'
version '0.5.1'

lua54 'yes'

shared_scripts {
  'shared/client_config.lua'
}

server_scripts {
  'config.lua',
  'shared/utils.lua',
  'shared/privacy.lua',
  'shared/framework.lua',
  'server/cloud.lua',
  'server/license.lua',
  'server/telemetry.lua',
  'server/webhooks.lua',
  'server/storage.lua',
  'server/punishments.lua',
  'server/bans.lua',
  'server/framework_adapters/standalone.lua',
  'server/framework_adapters/esx.lua',
  'server/framework_adapters/qbcore.lua',
  'server/framework_adapters/vrp.lua',
  'server/framework.lua',
  'server/firewall.lua',
  'server/economy_guard.lua',
  'server/framework_guards.lua',
  'server/admin_guard.lua',
  'server/entity_protection.lua',
  'server/detections.lua',
  'server/preflight.lua',
  'server/main.lua',
  'server/desktop_session.lua'
}

client_scripts {
  'client/heartbeat.lua',
  'client/player_checks.lua',
  'client/vehicle_checks.lua',
  'client/main.lua'
}
