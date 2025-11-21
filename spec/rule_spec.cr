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

describe "Gatekeeper.allow" do
  it "creates a rule with an exact regex when given a String path" do
    rule = Gatekeeper.allow("/admin")

    rule.path_regex.should eq /^\/admin$/
    rule.roles.should eq [] of String
    rule.methods.should be_nil
    rule.authenticator.should be_nil
  end

  it "does not match deeper paths when given a String (exact match only)" do
    rule = Gatekeeper.allow("/admin")

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)

    # /admin should match
    ctx1 = HTTP::Server::Context.new(
      HTTP::Request.new("GET", "/admin"),
      response
    )
    rule.matches?(ctx1).should be_true

    # /admin/dashboard should NOT match
    ctx2 = HTTP::Server::Context.new(
      HTTP::Request.new("GET", "/admin/dashboard"),
      response
    )
    rule.matches?(ctx2).should be_false
  end

  it "uses a Regex path as-is" do
    regex = /^\/api/
    rule = Gatekeeper.allow(regex, roles: ["api"])

    rule.path_regex.should eq regex
    rule.roles.should eq ["api"]
  end

  it "uses regex as-is, allowing prefix matches" do
    rule = Gatekeeper.allow(/^\/admin/)

    io = IO::Memory.new
    response = HTTP::Server::Response.new(io)

    ctx = HTTP::Server::Context.new(
      HTTP::Request.new("GET", "/admin/settings"),
      response
    )

    rule.matches?(ctx).should be_true
  end

  it "passes roles, methods and authenticator through to the rule" do
    auth = Gatekeeper.authenticator "test" do |ctx|
      nil.as(Gatekeeper::Identity?)
    end

    rule = Gatekeeper.allow(
      "/admin",
      roles: ["admin"],
      methods: ["POST"],
      authenticator: auth
    )

    rule.roles.should eq ["admin"]

    rule.methods.should_not be_nil
    rule.methods.not_nil!.should eq ["POST"]

    rule.authenticator.should_not be_nil
    rule.authenticator.should eq auth
  end

{% for method in Gatekeeper::HTTP_METHODS %}
    describe "Gatekeeper.allow_{{ method.id }}" do
      it "creates a rule with correct methods and exact match semantics" do
        rule = Gatekeeper.allow_{{ method.id }}("/path")

        rule.methods.should_not be_nil
        rule.methods.not_nil!.should eq [{{ method.stringify.upcase }}]

        io = IO::Memory.new
        response = HTTP::Server::Response.new(io)

        ctx_correct = HTTP::Server::Context.new(
          HTTP::Request.new({{ method.stringify.upcase }}, "/path"),
          response
        )

        ctx_wrong_path = HTTP::Server::Context.new(
          HTTP::Request.new({{ method.stringify.upcase }}, "/path/deeper"),
          response
        )

        other_method = "GET"
        {% if method.stringify.upcase == "GET" %}
          other_method = "POST"
        {% end %}

        ctx_wrong_method = HTTP::Server::Context.new(
          HTTP::Request.new(other_method, "/path"),
          response
        )

        rule.matches?(ctx_correct).should be_true
        rule.matches?(ctx_wrong_path).should be_false
        rule.matches?(ctx_wrong_method).should be_false
      end
    end
  {% end %}
end

describe "Gatekeeper.rules" do
  it "adds rules to the global config via the RuleSet builder" do
    cfg = Gatekeeper.config
    cfg.auth_rules.clear

    Gatekeeper.rules do |r|
      r.allow "/admin", roles: ["admin"]
      r.allow /^\/api/, roles: ["api"]
    end

    cfg.auth_rules.size.should eq 2

    admin_rule = cfg.auth_rules[0]
    api_rule   = cfg.auth_rules[1]

    admin_rule.path_regex.should eq /^\/admin$/
    admin_rule.roles.should eq ["admin"]

    api_rule.path_regex.should eq /^\/api/
    api_rule.roles.should eq ["api"]
  end

  {% for method in Gatekeeper::HTTP_METHODS %}
    describe "#allow_{{ method.id }}" do
      it "adds a rule to config.auth_rules with the correct HTTP method" do
        cfg = Gatekeeper.config
        cfg.auth_rules.clear

        Gatekeeper.rules do |r|
          r.allow_{{ method.id }}("/path")
        end

        cfg.auth_rules.size.should eq 1
        rule = cfg.auth_rules.first

        rule.path_regex.should eq /^\/path$/
        rule.methods.should_not be_nil
        rule.methods.not_nil!.should eq [{{ method.stringify.upcase }}]
      end
    end
  {% end %}
end
