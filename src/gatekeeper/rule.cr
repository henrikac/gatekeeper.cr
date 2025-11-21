module Gatekeeper
  struct Rule
    getter path_regex : Regex
    getter methods : Array(String)?
    getter roles : Array(String)
    getter authenticator : Authenticator?

    def initialize(@path_regex : Regex,
                   @roles : Array(String) = [] of String,
                   @methods : Array(String)? = nil,
                   @authenticator : Authenticator? = nil)
    end

    def matches?(ctx : HTTP::Server::Context) : Bool
      return false unless path_regex =~ ctx.request.path

      if m = methods
        return m.includes?(ctx.request.method)
      end

      return true
    end
  end

  HTTP_METHODS   = %w(get post put patch delete options)

  {% for method in HTTP_METHODS %}
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
end