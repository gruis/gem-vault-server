require "nos-record"
require "securerandom"

module GemVault
  module Server
    class ApiKey
      include NosRecord::Model
      include NosRecord::Model::MemoizeForeignAttr

      attr_reader :id
      alias :key :id

      attr_reader :created_on
      attr_reader :user_id

      def initialize(user)
        @created_on   = Time.new
        @id           = SecureRandom.hex
        @user         = user
        @user_id      = user.id
      end

      def user
        memoize(:user, User)
      end

      def user=(u)
        @user_id = u.id if u.is_a?(User)
        @user    = u
      end

      private

      def never_serialize
        super | [:@user]
      end

    end # class:ApiKey
  end # module::Server
end # module::GemVault

require "gem-vault/server/user"

