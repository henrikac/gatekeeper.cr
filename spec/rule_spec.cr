require "./spec_helper"

describe Gatekeeper::Rule do
  it "matches when path matches and no methods are specified" do
    rule = Gatekeeper::Rule.new(/^\/admin/)
    request = HTTP::Request.new("GET", "/admin/dashboard")
    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    ctx = HTTP::Server::Context.new(request, response)

    rule.matches?(ctx).should be_true
  end

  it "does not match when path does not match" do
    rule = Gatekeeper::Rule.new(/^\/admin/)
    request = HTTP::Request.new("GET", "/public")
    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)
    ctx = HTTP::Server::Context.new(request, response)

    rule.matches?(ctx).should be_false
  end

  it "matches only when HTTP method is in methods list" do
    rule = Gatekeeper::Rule.new(/^\/admin/, methods: ["POST"])
    get_request = HTTP::Request.new("GET", "/admin")
    post_request = HTTP::Request.new("POST", "/admin")

    io1 = IO::Memory.new
    resp1 = HTTP::Server::Response.new(io1)
    get_ctx = HTTP::Server::Context.new(get_request, resp1)

    io2 = IO::Memory.new
    resp2 = HTTP::Server::Response.new(io2)
    post_ctx = HTTP::Server::Context.new(post_request, resp2)

    rule.matches?(get_ctx).should be_false
    rule.matches?(post_ctx).should be_true
  end

  it "treats nil methods as 'all methods allowed'" do
    rule = Gatekeeper::Rule.new(/^\/admin/, methods: nil)
    get_request = HTTP::Request.new("GET", "/admin")
    post_request = HTTP::Request.new("POST", "/admin")

    io1 = IO::Memory.new
    resp1 = HTTP::Server::Response.new(io1)
    get_ctx = HTTP::Server::Context.new(get_request, resp1)

    io2 = IO::Memory.new
    resp2 = HTTP::Server::Response.new(io2)
    post_ctx = HTTP::Server::Context.new(post_request, resp2)

    rule.matches?(get_ctx).should be_true
    rule.matches?(post_ctx).should be_true
  end

  it "defaults roles to empty array" do
    rule = Gatekeeper::Rule.new(/^\/admin/)

    rule.roles.empty?.should be_true
  end

  it "can store a rule-specific authenticator" do
    auth = Gatekeeper::Authenticator.new { nil.as(Gatekeeper::Identity?) }
    rule = Gatekeeper::Rule.new(/^\/admin/, roles: ["ROLE_ADMIN"], authenticator: auth)

    rule.authenticator.should_not be_nil
  end
end
