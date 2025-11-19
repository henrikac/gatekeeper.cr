require "./**"

module Gatekeeper
  alias Authenticator = Proc(HTTP::Server::Context, Identity?)

  VERSION = "0.2.0"
end
