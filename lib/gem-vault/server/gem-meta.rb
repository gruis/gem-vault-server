require "nos-record"
require "gem-vault/server/gem"

module GemVault
  module Server
    class GemMeta
      include NosRecord::Model
      include NosRecord::Model::EasyAttrs

      attr_accessor :name
      alias :id :name
      attr_accessor :version
      attr_accessor :bug_tracker
      attr_accessor :wiki
      attr_accessor :documentation
      attr_accessor :mailing_list
      attr_accessor :source_code
      attr_accessor :downloads
      attr_accessor :version_downloads
      attr_accessor :project_path

      def gem
        @gem ||= @version ?
          Gem.each(name).find{|g| g.version.version == version } :
          Gem.each(name).sort{|b,a| a.version <=> b.version}.first
      end

      def gem_path
        "/gems/#{name}-#{version}.gem"
      end

      def project_path
        "/gems/#{name}"
      end

      def version
        @version ||= gem.version.version
      end

      def info
        return gem.description if gem.description && !gem.description.empty?
        gem.summary || ""
      end

      def to_hash
        data = {
          'name'              => gem.name,
          'downloads'         => 0,
          'version'           => gem.version.version,
          'version_downloads' => 0,
          'platform'          => gem.platform,
          'authors'           => gem.authors.join(", "),
          'info'              => info,
          'project_uri'       => project_path,
          'gem_uri'           => gem_path,
          'homepage_uri'      => gem.homepage
        }
        [
          :wiki,
          :documentation,
          :mailing_list,
          :source_code,
          :bug_tracker
        ].each do |key|
          data["#{key}_uri"] = send(key)
         end
        data['dependencies'] = gem.dependencies
        data
      end

      private

      def never_serialize
        super | [:@gem]
      end

    end # class::GemMeta
  end # module::Server
end # module::GemVault
