require "./spec_helper"

describe Gatekeeper::ContextHandler do
  it "stores the handler block and calls it" do
    called = false

    handler = Gatekeeper::ContextHandler.new do |ctx|
      called = true
      ctx.response.print "ok"
    end

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    ctx = HTTP::Server::Context.new(HTTP::Request.new("GET", "/"), response)

    handler.call(ctx)

    ctx.response.close

    called.should be_true

    raw = io.to_s
    body = raw.split("\r\n\r\n", 2)[1]

    body.should eq "ok"
  end
end
