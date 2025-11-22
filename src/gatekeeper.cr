require "./**"

module Gatekeeper
  def self.config(&)
    yield Config::INSTANCE
  end

  def self.config
    Config::INSTANCE
  end

  def self.authenticator(name : String? = nil, &block : HTTP::Server::Context -> Identity?)
    Authenticator.new(name, &block)
  end

  def self.rules(&block : RuleSet ->)
    builder = RuleSet.new(Gatekeeper.config)
    yield builder
  end

  def self.allow(
    path : String | Regex,
    roles : Array(String) = [] of String,
    methods : Array(String)? = nil,
    authenticator : Authenticator? = nil
  ) : Rule
    if path.is_a? String
      path = Regex.new("^#{Regex.escape(path)}$")
    end

    Rule.new(path, roles: roles, methods: methods, authenticator: authenticator)
  end

  {% for method in Gatekeeper::HTTP_METHODS %}
    def self.allow_{{method.id}}(
      path : String | Regex,
      roles : Array(String) = [] of String,
      authenticator : Authenticator? = nil
    ) : Rule
      allow(
        path,
        roles: roles,
        methods: [{{ method.stringify.upcase }}],
        authenticator: authenticator
      )
    end
  {% end %}
end
