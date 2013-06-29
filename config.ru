require "bundler"
Bundler.setup

require "gem-vault/server/http"

run GemVault::Server::Http
