module GemVault
  module Server
    module Error
      class StandardError < ::StandardError
        include Error
      end
    end
    class GemExists < StandardError; end
  end # module::Server
end # module::GemVault
