# Make OJ compatible with Sinatra::JSON
module Oj
  class << self
    def encode(*args)
      self.dump(*args)
    end
    def decode(*args)
      self.load(*args)
    end
  end
end
