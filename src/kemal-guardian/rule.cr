module Kemal::Guardian
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
end