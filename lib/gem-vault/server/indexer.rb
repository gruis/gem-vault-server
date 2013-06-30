require 'rubygems/command'
require 'rubygems/indexer'
require 'gem-vault/server'

module GemVault
  module Server
    class Indexer

      # @param [String] path
      def initialize(path = GemVault::Server.rootdir)
        if !File.exist?(path) || !File.directory?(path)
          raise(Errno::ENOENT "Unknown directory - #{path}").extend(Server::Error)
        end
        @path     = path
        @indexers = {}
      end

      # When run under Bundler the index method does not behave as expected. It
      # only indexes gems that have been accepted and loaded with Bundler.
      # @param [Hash] options
      # @option options [:build_legacy]
      # @option options [:build_modern] Generate indexes for RubyGems newer than 1.2.0
      # @option options [:update] Update modern indexes with gems added since the last update
      def index(options = {})
        system("gem generate_index -d #{@path} > /dev/null")
        # options = {:build_legacy => true, :build_modern => true}.merge(options)
        # indexer = indexer(options)
        # options[:update] ? indexer.update_index : indexer.generate_index
      end

      private

      def indexer(options)
        @indexers[options.keys.join] ||= ::Gem::Indexer.new(@path, options)
      end

    end # class::Indexer
  end # module::Server
end # module::GemVault
