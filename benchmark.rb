#!/usr/bin/env ruby

require "benchmark"
require "bundler"
Bundler.setup
require "gem-vault/server/user"
require "gem-vault/model/connection"
require "securerandom"

def report_per_sec(tms, n, space)
  per_sec = tms.real < 1 ? ((1/tms.real) * n) : n / tms.real
  puts "#{space} #{per_sec.round.to_s.gsub(/(\d)(?=(\d\d\d)+(?!\d))/, "\\1,")}/sec"
end

level_path  = File.expand_path("../tmp/bench.ldb", __FILE__)
sqlite_path = File.expand_path("../tmp/bench.sqlite", __FILE__)
kyoto_path  = File.expand_path("../tmp/bench.kch", __FILE__)

begin
  n       = 5_000
  n_human = "#{n / 1000}k"

  rand_users = n.times.map { |i| GemVault::Server::User.new(:id => i.to_s, :email => "bench.#{i}@gemvau.lt") }
  user_ids   = []
  user       = GemVault::Server::User.new(:id => "benchmark", :email => "benchmark@gemvau.lt")

  leveldb        = GemVault::Model::Connection::LevelDB.new(level_path)
  sqlite_memory  = GemVault::Model::Connection::Sqlite.new ":memory:"
  sqlite         = GemVault::Model::Connection::Sqlite.new(sqlite_path)
  redis          = GemVault::Model::Connection::Redis.new
  redisock       = GemVault::Model::Connection::Redis.new(:path => "/tmp/redis.sock")
  kcb            = GemVault::Model::Connection::KyotoCabinet.new(kyoto_path)


  to_test = [
    ["KyotoCabinet", kcb],
    ["LevelDB", leveldb],
    ["Redis", redis],
    ["Redis (Unix Socket)", redis],
    ["SQLite (Memory)", sqlite_memory],
    ["SQLite", sqlite]
  ]

  to_test.each do |name, con|
    $stderr.puts "\n\n#{name}"
    con.save(user)
    key = user.id

    unless con.get(key, GemVault::Server::User).is_a?(GemVault::Server::User)
      raise "Failed to retrieve user with #{key.inspect} key"
    end

    r_time  = nil
    w_time  = nil
    rw_time = nil

    Benchmark.bm(20) do |x|
      w_time = x.report("(#{n_human}) write:") do
        n.times do |i|
          user_ids << con.save(rand_users[i])
        end
      end
      report_per_sec(w_time, n, ("    "))

      r_time = x.report("(#{n_human}) read:") do
        n.times do |i|
          con.get(rand_users[i].id, GemVault::Server::User)
        end
      end
      report_per_sec(r_time, n, ("    "))

      rw_time = x.report("(#{n_human}) read & write:") do
        n.times do |i|
          con.get(rand_users[i].id, GemVault::Server::User)
          con.save(rand_users[i]) if i % 10
        end
      end
      report_per_sec(rw_time, n, ("    "))
    end
  end

ensure
  [level_path, sqlite_path, kyoto_path].each { |p| FileUtils.rm_rf(p) }
end

=begin
 * 2.6Ghz Intel Core i7
 * 16GB 1600 MHz DDr3
 * APPLE SSD SM512E
 * Ruby 2.0.0p195 (2013-05-14 revision 40734) [x86_64-darwin12.4.0]


KyotoCabinet
                           user     system      total        real
(25k) write:           0.200000   0.010000   0.210000 (  0.204523)
     122,236/sec
(25k) read:            0.220000   0.000000   0.220000 (  0.230515)
     108,453/sec
(25k) read & write:    0.460000   0.010000   0.470000 (  0.461851)
     54,130/sec


LevelDB
                           user     system      total        real
(25k) write:           0.210000   0.010000   0.220000 (  0.216882)
     115,270/sec
(25k) read:            0.230000   0.000000   0.230000 (  0.233257)
     107,178/sec
(25k) read & write:    0.520000   0.010000   0.530000 (  0.504035)
     49,600/sec


Redis
                           user     system      total        real
(25k) write:           1.410000   0.420000   1.830000 (  2.064798)
     12,108/sec
(25k) read:            1.470000   0.430000   1.900000 (  2.070735)
     12,073/sec
(25k) read & write:    2.880000   0.840000   3.720000 (  4.121688)
     6,065/sec


Redis (Unix Socket)
                           user     system      total        real
(25k) write:           1.360000   0.410000   1.770000 (  1.959406)
     12,759/sec
(25k) read:            1.490000   0.390000   1.880000 (  2.126249)
     11,758/sec
(25k) read & write:    2.850000   0.770000   3.620000 (  4.085881)
     6,119/sec


SQLite (Memory)
                           user     system      total        real
(25k) write:           0.970000   0.010000   0.980000 (  0.971103)
     25,744/sec
(25k) read:            0.960000   0.000000   0.960000 (  0.969800)
     25,779/sec
(25k) read & write:    2.090000   0.010000   2.100000 (  2.106009)
     11,871/sec


SQLite
                           user     system      total        real
(25k) write:           2.290000   7.760000  10.050000 ( 17.473671)
     1,431/sec
(25k) read:            1.210000   0.370000   1.580000 (  1.578052)
     15,842/sec
(25k) read & write:    4.020000   8.560000  12.580000 ( 21.033940)
     1,189/sec

=end
