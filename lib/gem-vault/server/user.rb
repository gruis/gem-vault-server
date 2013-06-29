require "nos-record"
require "bcrypt"

module GemVault
  module Server
    class User
      include NosRecord::Model
      include NosRecord::Model::EasyAttrs
      include NosRecord::Model::MemoizeForeignAttr

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

      def gen_api_key
        api_key.delete if api_key
        @api_key    = ApiKey.new(self).save
        @api_key_id = @api_key.id
        self
      end

      private

      def never_serialize
        super | [:@api_key]
      end

    end # class:User
  end # module::Server
end # module::GemVault

require "gem-vault/server/api-key"
