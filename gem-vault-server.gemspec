require File.expand_path("../lib/gem-vault/server/version", __FILE__)
require "rubygems"
::Gem::Specification.new do |s|
  s.name                      = 'gem-vault-server'
  s.version                   = GemVault::Server::VERSION
  s.platform                  = ::Gem::Platform::RUBY
  s.authors                   = ['Caleb Crane']
  s.email                     = ['gem-vault-server@simulacre.org']
  s.homepage                  = 'http://github.com/simulacre/gem-vault-server'
  s.summary                   = 'An EventMachine compatible net-ssh'
  s.description               = ''
  s.required_rubygems_version = ">= 1.3.6"
  s.files                     = Dir["lib/**/*.rb", "bin/*", "*.md"]
  s.require_paths             = ['lib']
  s.executables               = Dir["bin/*"].map{|f| f.split('/')[-1] }
  s.license                   = 'MIT'

  # If you have C extensions, uncomment this line
  # s.extensions = "ext/extconf.rb"
  s.add_dependency 'builder'
  s.add_dependency 'thin'
  s.add_dependency 'sinatra', "~>1.4.3"
  s.add_dependency 'sinatra-contrib'
  s.add_dependency 'rack-flash3'
  s.add_dependency 'warden'
  s.add_dependency 'bcrypt-ruby'
end
