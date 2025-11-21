# Gatekeeper

[![CI](https://github.com/henrikac/gatekeeper.cr/actions/workflows/ci.yml/badge.svg)](https://github.com/henrikac/gatekeeper.cr/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/henrikac/gatekeeper.cr)](https://github.com/henrikac/gatekeeper.cr/releases)
[![License](https://img.shields.io/github/license/henrikac/gatekeeper.cr)](./LICENSE)

A small authorization middleware with pluggable authenticators.
- You define rules for your routes (using regex)
- You define one or more authenticators that resolve a user identity
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

Gatekeeper.config do |config|
  config.on_unauthenticated = Gatekeeper::ContextHandler.new do |ctx|
    ctx.response.print "You must log in first."
  end

  config.on_unauthorized = Gatekeeper::ContextHandler.new do |ctx|
    ctx.response.print "You do not have permission."
  end

  # Simple authenticator example
  config.authenticators << Gatekeeper.authenticator do |ctx|
    Gatekeeper::IdentityUser(Int32).new(1, Set{"admin"})
  end
end

# Define rules using the rule DSL
Gatekeeper.rules do |r|
  r.allow "/admin", roles: ["admin"]   # exact match
  r.allow /^\//                        # allow everything else
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
  - If the user has any of the allowed roles → request continues to the next handler

Rules are evaluated in the order they were added.

### Authenticators

An authenticator is a small object (`Gatekeeper::Authenticator`) that knows how to extract an `Identity` from a request.  
If an authenticator returns `nil`, Gatekeeper moves on to the next one.  
The first authenticator that returns a user “wins”.  
A rule may also define its own authenticator, which overrides the global ones.

```crystal
my_special_auth = Gatekeeper.authenticator do |ctx|
  # your logic here
end

Gatekeeper::Rule.new(/^\/private/, roles: ["member"], authenticator: my_special_auth)
```

#### Named authenticator

Authenticators may also be given a name, which is useful for debugging or when you have several different authentication strategies in the same application.

```crystal
token_auth = Gatekeeper.authenticator "token auth" do |ctx|
  token = ctx.request.headers["Authorization"]?
  next nil unless token

  user = UserRepository.find_by_token(token)
  next nil unless user

  Gatekeeper::IdentityUser(Int32).new(user.id, Set{"member"})
end

config.authenticators << token_auth
```

You can also attach a named authenticator directly to a rule.

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
config.authenticators << Gatekeeper.authenticator do |ctx|
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

- `path_regex`: matched against `ctx.request.path`
- `roles`: user must have at least one of these roles
- `methods`: optional HTTP method filter (GET/POST/PUT/DELETE/etc.)
- `authenticator`: optional override for this rule only

Rules are evaluated in the order they were added.
The first matching rule is used.

### Rule helpers

Gatekeeper includes a small convenience API to make rule definition more ergonomic.

#### `Gatekeeper.allow`

A helper that builds a `Rule` without needing to call `Rule.new` directly:

```crystal
rule = Gatekeeper.allow(
  path : String | Regex,
  roles : Array(String) = [],
  methods : Array(String)? = nil,
  authenticator : Gatekeeper::Authenticator? = nil
)
```

**Path semantics:**

- When `path` is a **String**, Gatekeeper converts it into an **exact match** regex.  
  Example:  
  `"/admin"` becomes `/^\/admin$/`, matching **only** `/admin`.

- When `path` is a **Regex**, it is used **as-is**.  
  Useful for prefixes or patterns such as:  
  `/^\/api/` which matches `/api`, `/api/v1`, etc.

Example:

```crystal
Gatekeeper.allow("/admin", roles: ["admin"])
Gatekeeper.allow(/^\/api/, roles: ["api_user"])
```

---

### Rule DSL (`Gatekeeper.rules`)

Gatekeeper also provides a small builder-style DSL for defining multiple rules
in a clean and structured way. It is simply syntactic sugar around `Gatekeeper.allow`.

```crystal
Gatekeeper.rules do |r|
  r.allow "/admin", roles: ["admin"]
  r.allow /^\/api/, roles: ["api_user"]
end
```

This is equivalent to calling `Gatekeeper.allow` manually and pushing the rules
into the configuration, but keeps rule definitions grouped and readable.

Internally, this DSL just appends rules to `Gatekeeper.config.auth_rules`.

### ContextHandler

`ContextHandler` is a small wrapper used for callbacks such as
`on_unauthenticated` and `on_unauthorized`. It simply holds a block that
receives the current `HTTP::Server::Context` and writes a custom response.

```crystal
config.on_unauthenticated = Gatekeeper::ContextHandler.new do |ctx|
  ctx.response.print "You must log in first."
end

config.on_unauthorized = Gatekeeper::ContextHandler.new do |ctx|
  ctx.response.print "You do not have permission."
end
```

Gatekeeper calls these handlers internally when:

- no authenticator returns a user → **401 Unauthorized**
- a user exists but lacks the required role → **403 Forbidden**

If no handler is set, Gatekeeper simply returns the status code
without a body.

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
