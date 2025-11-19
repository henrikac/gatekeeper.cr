require "./spec_helper"

describe Gatekeeper::Config do
  it "returns the same instance from Gatekeeper.config" do
    c1 = Gatekeeper.config
    c2 = Gatekeeper.config

    c1.should be c2
  end

  it "yields the singleton instance to the config block" do
    yielded = nil.as(Gatekeeper::Config?)

    Gatekeeper.config do |c|
      yielded = c
    end

    yielded.should be Gatekeeper.config
  end

  it "has empty authenticators and auth_rules by default" do
    cfg = Gatekeeper.config

    cfg.authenticators.empty?.should be_true
    cfg.auth_rules.empty?.should be_true
  end

  it "allows adding authenticators" do
    cfg = Gatekeeper.config
    cfg.authenticators.clear

    auth = ->(ctx : HTTP::Server::Context) { nil.as(Gatekeeper::Identity?) }
    cfg.authenticators << auth

    cfg.authenticators.size.should eq 1
    cfg.authenticators.first.should eq auth
  end

  it "allows adding rules" do
    cfg = Gatekeeper.config

    rule = Gatekeeper::Rule.new(/^\/admin/)
    cfg.auth_rules << rule

    cfg.auth_rules.size.should eq 1
    cfg.auth_rules.first.should eq rule
  end

  it "allows setting unauthenticated and unauthorized callbacks" do
    cfg = Gatekeeper.config

    unauth_called = false
    unauthorized_called = false

    cfg.on_unauthenticated = ->(ctx : HTTP::Server::Context) do
      unauth_called = true
    end

    cfg.on_unauthorized = ->(ctx : HTTP::Server::Context) do
      unauthorized_called = true
    end

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    ctx = HTTP::Server::Context.new(HTTP::Request.new("GET", "/"), response)

    cfg.on_unauthenticated.try &.call ctx
    cfg.on_unauthorized.try &.call ctx

    unauth_called.should be_true
    unauthorized_called.should be_true
  end
end
