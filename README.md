# Gatekeeper

[![CI](https://github.com/henrikac/gatekeeper.cr/actions/workflows/ci.yml/badge.svg)](https://github.com/henrikac/gatekeeper.cr/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/henrikac/gatekeeper.cr)](https://github.com/henrikac/gatekeeper.cr/releases)
[![License](https://img.shields.io/github/license/henrikac/gatekeeper.cr)](./LICENSE)

A small authorization middleware with pluggable authentication.
- You define rules for your routes (using regex)
- You define one or more authenticators (functions that return a user identity)
- Gatekeeper checks whether the user is allowed to access the route

It does **not** implement login, sessions, JWT validation or password handling.
You bring the authentication mechanism — Gatekeeper enforces access rules.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     gatekeeper:
       github: henrikac/gatekeeper.cr
   ```

2. Run `shards install`

## Usage

### Configure Gatekeeper

```crystal
require "gatekeeper"

# Configure Gatekeeper
Gatekeeper.config do |config|
  # Called when no authenticator can produce a user
  config.on_unauthenticated = ->(ctx : HTTP::Server::Context) do
    ctx.response.print "You must log in first."
  end

  # Called when a user exists but lacks the required roles
  config.on_unauthorized = ->(ctx : HTTP::Server::Context) do
    ctx.response.print "You do not have permission."
  end

  # Only allow users with role "admin" to access /admin
  config.auth_rules << Gatekeeper::Rule.new(
    /^\/admin/,
    roles: ["admin"]
  )

  # Allow everyone to access everything else (no roles)
  config.auth_rules << Gatekeeper::Rule.new(/^\//)

  # Simple authenticator that always logs in an "admin" user
  config.authenticators << ->(ctx : HTTP::Server::Context) : Gatekeeper::Identity? do
    # In real code you’d look at cookies / headers / session etc.
    Gatekeeper::IdentityUser(Int32).new(1, Set{"admin"})
  end
end
```

### Basic example with HTTP::Server

```crystal
require "http/server"
require "gatekeeper"

class AppHandler
  include HTTP::Handler

  def call(context)
    case context.request.path
    when "/"
      context.response.print "Hello World!"
    when "/admin"
      context.response.print "Hello admin!"
    else
      context.response.status = HTTP::Status::NOT_FOUND
      context.response.print "Not found"
    end
  end
end

Gatekeeper.config do |config|
  # …
end

handlers = [
  Gatekeeper::AuthHandler.new,
  AppHandler.new,
]

server = HTTP::Server.new(handlers)

address = server.bind_tcp "0.0.0.0", 3000
puts "Listening on http://#{address}"
server.listen
```

### Basic example using Kemal

```crystal
require "kemal"
require "gatekeeper"

add_handler Gatekeeper::AuthHandler.new

Gatekeeper.config do |config|
  # …
end

get "/" do
  "Hello world"
end

get "/admin" do
  "Hello admin"
end

Kemal.run
```

### How it works

Gatekeeper processes requests in this order:
1. No rules defined: request is allowed
2. Rule exists but does not match: request is allowed
3. Rule matches but has no roles: request is allowed
4. Rule matches + roles required → authenticators run
  - If no authenticator returns a user → `401 Unauthorized`
  - If a user exists but does not have a required role → `403 Forbidden`
  - If the user has any of the allowed roles → request is forwarded

Rules are evaluated in the order they were added.

### Authenticators

An authenticator is any `Proc` that takes a `HTTP::Server::Context` and returns:
- an `Identity` (authenticated user), or
- nil (not authenticated)

All authenticators are tried in order until one returns a user.
You can also assign an authenticator directly to a specific rule:

```crystal
my_special_auth = ->(ctx : HTTP::Server::Context) : Gatekeeper::Identity? do
  # your logic here
end

Gatekeeper::Rule.new(/^\/private/, roles: ["member"], authenticator: my_special_auth)
```

### Identity

Gatekeeper needs an identity type that represents the authenticated user.
Every identity must implement:

```crystal
abstract class Gatekeeper::Identity
  abstract def roles : Set(String)
end
```

Gatekeeper ships with a simple identity type:

```crystal
class Gatekeeper::IdentityUser(ID) < Gatekeeper::Identity
  getter id : ID
  getter roles : Set(String)
end
```

You can use any ID type (`Int32`, `String`, `UUID`, etc.).
To define your own identity type, inherit from `Identity`:

```crystal
class MyUser < Gatekeeper::Identity
  getter roles : Set(String)
  getter email : String
end
```

### Authenticator example

```crystal
config.authenticators << ->(ctx : HTTP::Server::Context) : Gatekeeper::Identity? do
  token = ctx.request.headers["Authorization"]?
  next nil unless token

  user = MyUserRepository.find_by_token(token)
  next nil unless user

  Gatekeeper::IdentityUser(Int32).new(user.id, Set{"admin"})
end
```

### Rules

A rule defines when and how Gatekeeper enforces authorization:

```crystal
Gatekeeper::Rule.new(
  path_regex : Regex,
  roles : Array(String) = [],
  methods : Array(String)? = nil,
  authenticator : Gatekeeper::Authenticator? = nil
)
```

- `path_regex`: matched against ctx.request.path
- `roles`: user must have at least one of these roles
- `methods`: optional HTTP method filter (GET/POST/PUT/DELETE/etc.)
- `authenticator`: optional override for this rule only

Rules are evaluated in the order they were added.
The first matching rule is used.

### ⚠️ Security Warning

Gatekeeper does not perform authentication.
It only consumes the identity returned by your authenticators and enforces authorization rules.
Make sure your authentication mechanism (sessions, tokens, cookies, etc.) is secure.

## Contributing

1. Fork it (<https://github.com/henrikac/gatekeeper.cr/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Henrik Christensen](https://github.com/henrikac) - creator and maintainer
