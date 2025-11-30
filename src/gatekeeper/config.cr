module Gatekeeper
  class Config
    INSTANCE = self.new

    getter authenticators : Array(Authenticator) = [] of Authenticator
    getter auth_rules : Array(Rule) = [] of Rule

    property on_unauthenticated : ContextHandler?
    property on_unauthorized : ContextHandler?
    property role_hierarchy : Hash(String, Array(String)) = {} of String => Array(String)

    def initialize
    end
  end
end
