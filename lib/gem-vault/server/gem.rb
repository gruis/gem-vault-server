require "stringio"
require "gem-vault/server"
require "rubygems/package"

module GemVault
  module Server
    class Gem
      class << self
        include Enumerable

        def each(name = nil, &blk)
          if name
            by_name[name].each(&blk) if block_given?
            by_name[name]
          else
            gems(&blk)
          end
        end

        def names
          map(&:name).uniq
        end

        def add(raw_gem)
          pkg      = ::Gem::Package.open(StringIO.new(raw_gem), "r") { |p| p.metadata }
          filename = "#{pkg.name}-#{pkg.version}.gem"
          path     = File.join(GemVault::Server.gemdir, filename)
          File.exists?(path) && raise(Errno::EEXIST, filename).extend(Error)
          File.open(path, "w") { |io| io.write(raw_gem) }
          new(path).tap { |g| cache(g) }
        end

        def cache(gem)
          by_name[gem.name] << gem unless by_name[gem.name].include?(gem)
          gems << gem unless gems.include?(gem)
        end

        def refresh!
          @gems    = nil
          @by_name = nil
        end

        private

        def gems(&blk)
          if @gems
            @gems.each(&blk) if block_given?
          else
            glob  = File.join(GemVault::Server.gemdir, "*.gem")
            @gems = block_given? ?
              Dir[glob].map { |path| new(path).tap(&blk) } :
              Dir[glob].map { |path| new(path) }
          end
          @gems
        end

        def by_name
          @by_name ||= Hash.new { |h,k| h[k] = each.select { |g| g.name == k } }
        end
      end # class << self


      def initialize(path)
        @path = path
      end

      [:name,
       :version,
       :authors,
       :description,
       :summary,
       :email,
       :project_uri,
       :homepage,
       :platform
      ].each do |key|
        define_method(key) do
          iv = :"@#{key}"
          return instance_variable_get(iv) if instance_variable_defined?(iv)
          instance_variable_set(iv, spec.send(key))
        end
      end

      def dependencies
        runtime = []
        devel   = []
        spec.dependencies
          .sort{|a,b| a.name.to_s <=> b.name.to_s }
          .each do |d|
          (d.type == :runtime ? runtime : devel)
            .push({'name' => d.name.to_s, 'requirements' => d.requirement.to_s })
        end
        {'development' => devel, 'runtime' => runtime}
      end

      def spec
        @spec ||=  open { |pkg| pkg.metadata }

      # https://github.com/rubygems/rubygems.org/blob/15b6dd6d5f/config/initializers/forbidden_yaml.rb
      # rescue Psych::WhitelistException => e
      #   # "Attempted YAML metadata exploit: #{e}"
      #   raise StandardError, "RubyGems.org cannot process this gem.\nThe metadata is invalid.\n#{e}"
      rescue Gem::Package::FormatError
        raise StandardError, "RubyGems.org cannot process this gem.\nPlease try rebuilding it" +
               " and installing it locally to make sure it's valid."
      rescue Exception => e
        raise StandardError, "RubyGems.org cannot process this gem.\nPlease try rebuilding it" +
               " and installing it locally to make sure it's valid.\n" +
               "Error:\n#{e.message}}"
      end


      private

      def open(&blk)
        ::Gem::Package.open(File.open(@path), "r", &blk)
      end
    end # class::Gem
  end # module::Server
end # module::GemVault
