require "http/server/handler"
require "spec"
require "../src/**"

class DummyHandler
  include HTTP::Handler

  getter called = false

  def call(context)
    @called = true
    context.response.status_code = 200
  end
end

def reset_guardian_config
  config = Gatekeeper.config
  config.auth_rules.clear
  config.authenticators.clear
  config.on_unauthenticated = nil
  config.on_unauthorized = nil
end

def create_request_and_return_io_and_context(handler : HTTP::Handler, request : HTTP::Request)
  io = IO::Memory.new
  response = HTTP::Server::Response.new(io)
  context = HTTP::Server::Context.new(request, response)
  handler.call(context)
  response.close
  io.rewind
  {io, context}
end

Spec.before_each do
  reset_guardian_config
end