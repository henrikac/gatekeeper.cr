module Gatekeeper
  alias IdentityResolver = Proc(HTTP::Server::Context, Identity?)

  struct Authenticator
    getter resolver : IdentityResolver
    getter name : String?

    def initialize(name : String? = nil, &block : HTTP::Server::Context -> Identity?)
      @name = name
      @resolver = block
    end

    def call(ctx : HTTP::Server::Context) : Identity?
      @resolver.call(ctx)
    end
  end
end