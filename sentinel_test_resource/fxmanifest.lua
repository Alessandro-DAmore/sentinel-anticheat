fx_version 'cerulean'
game 'gta5'

name 'Sentinel Test Resource'
author 'Sentinel Security'
description 'Manual FXServer smoke tests for Sentinel AC.'
version '0.1.0'

lua54 'yes'

server_scripts {
  'server/main.lua'
}

client_scripts {
  'client/main.lua'
}
