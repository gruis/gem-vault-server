require "nos-record"
require "bcrypt"

module GemVault
  module Server
    class User
      include NosRecord::Model
      include NosRecord::Model::EasyAttrs
      include NosRecord::Model::MemoizeForeignAttr
      include NosRecord::Model::HideIdAttrs

      attr_accessor :uid
      alias :id :uid
      attr_accessor :first_name
      attr_accessor :last_name
      attr_accessor :email
      attr_reader :created_on

      def initialize(attrs = {})
        super
        @created_on = Time.new
      end

      def to_hash
        super.tap do |h|
          h['admin'] = admin?
        end
      end

      def admin?
        !!@admin
      end

      def admin=(v)
        @admin = !!v
      end

      def password=(pass)
        @password = BCrypt::Password.create(pass)
      end

      def password
        BCrypt::Password.new(@password)
      end

      def authenticate(p)
        password == p
      end

      def api_key
        memoize(:api_key, ApiKey)
      end

      def del_api_key
        return unless api_key
        api_key.delete
        @api_key_id = nil
        self
      end

      def gen_api_key
        api_key.delete if api_key
        @api_key    = ApiKey.new(self).save
        @api_key_id = @api_key.id
        self
      end

      def gem_ids
        @gem_ids ||= GemMeta.select {|g| g.owner_ids.include?(id) }.map(&:id)
      end

      def gems
        @gems ||= gem_ids.map{|g| GemMeta.get(g) }
      end

      def add_gem(meta)
        gem_ids << meta.id unless gem_ids.include?(meta.id)
        gems << meta unless gems.map(&:id).include?(meta.id)
        self
      end

      def del_gem(gem)
        gem_ids.delete(gem.id)
        gems.delete_if { |g| g.id == gem.id }
        self
      end

      def own?(gem)
        gem.own?(self)
      end

      private

      def never_serialize
        super | [:@api_key, :@gems]
      end

    end # class:User
  end # module::Server
end # module::GemVault

require "gem-vault/server/api-key"
