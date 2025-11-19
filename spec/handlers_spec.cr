require "./spec_helper"

describe Gatekeeper::AuthHandler do
  it "allows when rule has no roles" do
    config = Gatekeeper.config
    config.auth_rules << Gatekeeper::Rule.new(/^\//)
    config.authenticators << ->(ctx : HTTP::Server::Context) { nil.as(Gatekeeper::Identity?) }

    handler = Gatekeeper::AuthHandler.new
    next_handler = DummyHandler.new
    handler.next = next_handler

    request = HTTP::Request.new("GET", "/")
    io, ctx = create_request_and_return_io_and_context(handler, request)

    next_handler.called.should be_true
    ctx.response.status_code.should eq 200
  end

  it "allows when rule has roles and user has required role" do
    config = Gatekeeper.config
    config.auth_rules << Gatekeeper::Rule.new(/^\/admin/, roles: ["ROLE_ADMIN"])
    config.authenticators << ->(ctx : HTTP::Server::Context) : Gatekeeper::Identity? do
      Gatekeeper::IdentityUser(Int32).new 1, Set.new(["ROLE_ADMIN"])
    end

    handler = Gatekeeper::AuthHandler.new
    next_handler = DummyHandler.new
    handler.next = next_handler

    request = HTTP::Request.new("GET", "/admin")
    io, ctx = create_request_and_return_io_and_context(handler, request)

    next_handler.called.should be_true
    ctx.response.status_code.should eq 200
  end

  it "returns 401 when the rule requires roles and no authenticator provides a user" do
    config = Gatekeeper.config
    config.auth_rules << Gatekeeper::Rule.new(/^\/admin/, roles: ["ROLE_ADMIN"])
    config.authenticators << ->(ctx : HTTP::Server::Context) { nil.as(Gatekeeper::Identity?) }

    handler = Gatekeeper::AuthHandler.new
    request = HTTP::Request.new("GET", "/admin")

    io, ctx = create_request_and_return_io_and_context(handler, request)

    ctx.response.status_code.should eq 401
  end

  it "returns 403 when the rule requires roles and authenticator provides a user without valid role" do
    config = Gatekeeper.config
    config.auth_rules << Gatekeeper::Rule.new(/^\/admin/, roles: ["ROLE_ADMIN"])
    config.authenticators << ->(ctx : HTTP::Server::Context) : Gatekeeper::Identity? do
      Gatekeeper::IdentityUser(Int32).new 1, Set.new(["ROLE_USER"])
    end

    handler = Gatekeeper::AuthHandler.new
    request = HTTP::Request.new("GET", "/admin")

    io, ctx = create_request_and_return_io_and_context(handler, request)

    ctx.response.status_code.should eq 403
  end

  it "uses rule-specific authenticator instead of global authenticators" do
    config = Gatekeeper.config

    rule_auth_called = false
    rule_auth = ->(ctx : HTTP::Server::Context) : Gatekeeper::Identity? do
      rule_auth_called = true
      Gatekeeper::IdentityUser(Int32).new 1, Set.new(["ROLE_ADMIN"])
    end

    config.auth_rules << Gatekeeper::Rule.new(
      /^\/admin/,
      roles: ["ROLE_ADMIN"],
      authenticator: rule_auth
    )

    config.authenticators << ->(ctx : HTTP::Server::Context) : Gatekeeper::Identity? do
      raise "global authenticator should not be called"
      nil
    end

    handler = Gatekeeper::AuthHandler.new
    next_handler = DummyHandler.new
    handler.next = next_handler

    request = HTTP::Request.new("GET", "/admin")
    io, ctx = create_request_and_return_io_and_context(handler, request)

    rule_auth_called.should be_true
    next_handler.called.should be_true
    ctx.response.status_code.should eq 200
  end

  it "passes through when rules exist but none match the request" do
    config = Gatekeeper.config
    config.auth_rules << Gatekeeper::Rule.new(/^\/admin/, roles: ["ROLE_ADMIN"])

    handler = Gatekeeper::AuthHandler.new
    next_handler = DummyHandler.new
    handler.next = next_handler

    request = HTTP::Request.new("GET", "/public")
    io, ctx = create_request_and_return_io_and_context(handler, request)

    next_handler.called.should be_true
    ctx.response.status_code.should eq 200
  end

  it "ignores rule when HTTP method does not match" do
    config = Gatekeeper.config
    config.auth_rules << Gatekeeper::Rule.new(/^\/admin/, roles: ["ROLE_ADMIN"], methods: ["POST"])

    handler = Gatekeeper::AuthHandler.new
    next_handler = DummyHandler.new
    handler.next = next_handler

    request = HTTP::Request.new("GET", "/admin")
    io, ctx = create_request_and_return_io_and_context(handler, request)

    next_handler.called.should be_true
    ctx.response.status_code.should eq 200
  end

  it "uses the first authenticator that returns a user" do
    config = Gatekeeper.config
    config.auth_rules << Gatekeeper::Rule.new(/^\/admin/, roles: ["ROLE_ADMIN"])

    calls = [] of Int32

    config.authenticators << ->(ctx : HTTP::Server::Context) : Gatekeeper::Identity? do
      calls << 1
      nil
    end

    config.authenticators << ->(ctx : HTTP::Server::Context) : Gatekeeper::Identity? do
      calls << 2
      Gatekeeper::IdentityUser(Int32).new 1, Set{"ROLE_ADMIN"}
    end

    config.authenticators << ->(ctx : HTTP::Server::Context) : Gatekeeper::Identity? do
      calls << 3
      nil
    end

    handler = Gatekeeper::AuthHandler.new
    next_handler = DummyHandler.new
    handler.next = next_handler

    request = HTTP::Request.new("GET", "/admin")
    io, ctx = create_request_and_return_io_and_context(handler, request)

    calls.should eq [1, 2]
    next_handler.called.should be_true
    ctx.response.status_code.should eq 200
  end

  it "returns 401 when rule authenticator is present but returns nil" do
    config = Gatekeeper.config

    rule_auth_called = false
    rule_auth = ->(ctx : HTTP::Server::Context) : Gatekeeper::Identity? do
      rule_auth_called = true
      nil
    end

    config.auth_rules << Gatekeeper::Rule.new(/^\/admin/, roles: ["ROLE_ADMIN"], authenticator: rule_auth)

    config.authenticators << ->(ctx : HTTP::Server::Context) : Gatekeeper::Identity? do
      raise "global authenticator should not be called"
      nil
    end

    handler = Gatekeeper::AuthHandler.new
    next_handler = DummyHandler.new
    handler.next = next_handler

    request = HTTP::Request.new("GET", "/admin")
    io, ctx = create_request_and_return_io_and_context(handler, request)

    rule_auth_called.should be_true
    next_handler.called.should be_false
    ctx.response.status_code.should eq 401
  end

  it "calls on_unauthenticated callback on 401" do
    config = Gatekeeper.config
    config.auth_rules << Gatekeeper::Rule.new(/^\/admin/, roles: ["ROLE_ADMIN"])

    config.authenticators << ->(ctx : HTTP::Server::Context) { nil.as(Gatekeeper::Identity?) }

    called = false
    config.on_unauthenticated = ->(ctx : HTTP::Server::Context) do
      called = true
      ctx.response.print "custom 401"
    end

    handler = Gatekeeper::AuthHandler.new
    next_handler = DummyHandler.new
    handler.next = next_handler

    request = HTTP::Request.new("GET", "/admin")
    io, ctx = create_request_and_return_io_and_context(handler, request)

    called.should be_true
    next_handler.called.should be_false
    ctx.response.status_code.should eq 401
    io.to_s.should contain "custom 401"
  end

  it "calls on_unauthorized callback on 403" do
    config = Gatekeeper.config
    config.auth_rules << Gatekeeper::Rule.new(/^\/admin/, roles: ["ROLE_ADMIN"])

    user = Gatekeeper::IdentityUser(Int32).new 1, Set{"ROLE_USER"}
    config.authenticators << ->(ctx : HTTP::Server::Context) { user.as(Gatekeeper::Identity?) }

    called = false
    config.on_unauthorized = ->(ctx : HTTP::Server::Context) do
      called = true
      ctx.response.print "nope"
    end

    handler = Gatekeeper::AuthHandler.new
    next_handler = DummyHandler.new
    handler.next = next_handler

    request = HTTP::Request.new("GET", "/admin")
    io, ctx = create_request_and_return_io_and_context(handler, request)

    called.should be_true
    next_handler.called.should be_false
    ctx.response.status_code.should eq 403
    io.to_s.should contain "nope"
  end
end
