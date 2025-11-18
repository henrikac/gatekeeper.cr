module Kemal::Guardian
  class Config
    INSTANCE = self.new

    getter authenticators : Array(Authenticator) = [] of Authenticator
    getter auth_rules : Array(Rule) = [] of Rule

    property on_unauthenticated : Proc(HTTP::Server::Context, Nil)?
    property on_unauthorized : Proc(HTTP::Server::Context, Nil)?

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
