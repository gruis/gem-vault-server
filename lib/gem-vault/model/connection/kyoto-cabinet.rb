require "kyotocabinet"

module GemVault
  module Model
    class Connection
      class KyotoCabinet < Connection

        DBNAME = "gem-vault.kch"

        def initialize(path = DBNAME)
          @path = path
          open
        end


        private

        def retrv(key)
          @db.get(key)
        end

        def store(key, val)
          @db.set(key, val) || raise("set error '#{key}': #{db.error}")
          self
        end

        def unstore(key)
          @db.del(key)
          self
        end

        def values(klass = nil)
          return @db.map{|k,v| v }.each if klass.nil?
          recs = @db.get_bulk(@db.match_prefix(key_for_class(klass)))
          recs && recs.values
        end

        def close_store
          @db.close
        end

        def open_store
          db = ::KyotoCabinet::DB::new
          unless db.open(@path, ::KyotoCabinet::DB::OWRITER | ::KyotoCabinet::DB::OCREATE)
            raise "open error '#{path}': #{db.error}"
          end
          db
        end

      end # class::KyotoCabinet < Connection
    end # class::Connection
  end # module::Model
end # module::GemVault