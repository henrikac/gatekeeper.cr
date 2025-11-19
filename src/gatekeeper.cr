require "./**"

module Gatekeeper
  alias Authenticator = Proc(HTTP::Server::Context, Identity?)

  VERSION = "0.1.0"
end
