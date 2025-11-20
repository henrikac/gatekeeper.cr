require "./spec_helper"

describe Gatekeeper::Authenticator do
  it "stores the resolver block and calls it" do
    called = false
    auth = Gatekeeper::Authenticator.new do |ctx|
      called = true
      nil
    end

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    ctx = HTTP::Server::Context.new(HTTP::Request.new("GET", "/"), response)

    auth.call(ctx)
    called.should be_true
  end

  it "stores the optional name" do
    auth = Gatekeeper::Authenticator.new("basic auth") { nil }

    auth.name.should eq "basic auth"
  end

  it "allows constructing via Gatekeeper.authenticator" do
    auth = Gatekeeper.authenticator "my auth" do
      Gatekeeper::IdentityUser(Int32).new(1, Set{"ROLE_USER"})
    end

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    ctx = HTTP::Server::Context.new(HTTP::Request.new("GET", "/"), response)

    result = auth.call(ctx)
    result.should be_a(Gatekeeper::IdentityUser(Int32))
    auth.name.should eq "my auth"
  end

  it "allows constructing via Gatekeeper.authenticator without a name" do
    auth = Gatekeeper.authenticator do
      Gatekeeper::IdentityUser(Int32).new(1, Set{"ROLE_USER"})
    end

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    ctx = HTTP::Server::Context.new(HTTP::Request.new("GET", "/"), response)

    result = auth.call(ctx)
    result.should be_a(Gatekeeper::IdentityUser(Int32))
    auth.name.should be_nil
  end
end
