module Gatekeeper
  class RuleSet
    def initialize(@config : Config)
    end

    def allow(
      path : String | Regex,
      roles : Array(String) = [] of String,
      methods : Array(String)? = nil,
      authenticator : Authenticator? = nil
    ) : Rule
      rule = Gatekeeper.allow(
        path,
        roles: roles,
        methods: methods,
        authenticator: authenticator
      )

      @config.auth_rules << rule
      rule
    end

    {% for method in Gatekeeper::HTTP_METHODS %}
      def allow_{{ method.id }}(
        path : String | Regex,
        roles : Array(String) = [] of String,
        authenticator : Gatekeeper::Authenticator? = nil
      ) : Rule
        rule = Gatekeeper.allow_{{ method.id }}(path, roles: roles, authenticator: authenticator)
        @config.auth_rules << rule
        rule
      end
    {% end %}
  end

  def self.rules(&block : RuleSet ->)
    builder = RuleSet.new(Gatekeeper.config)
    yield builder
  end
end
