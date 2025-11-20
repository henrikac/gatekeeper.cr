module Gatekeeper
  class Config
    INSTANCE = self.new

    getter authenticators : Array(Authenticator) = [] of Authenticator
    getter auth_rules : Array(Rule) = [] of Rule

    property on_unauthenticated : ContextHandler?
    property on_unauthorized : ContextHandler?

    def initialize
    end
  end

  def self.config(&)
    yield Config::INSTANCE
  end

  def self.config
    Config::INSTANCE
  end
end
