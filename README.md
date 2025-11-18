# kemal-guardian

A small authorization middleware for [Kemal](https://kemalcr.com) with pluggable authentication.
- You define rules for your routes (using regex)
- You define one or more authenticators (functions that return a user identity)
- kemal-guardian checks whether the user is allowed to access the route

It does **not** implement login, sessions, JWT validation or password handling.
You bring the authentication mechanism — kemal-guardian enforces access rules.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     kemal-guardian:
       github: henrikac/kemal-guardian
   ```

2. Run `shards install`

## Usage

```crystal
require "kemal-guardian"

add_handler Kemal::Guardian::AuthHandler.new

Kemal::Guardian.config do |config|
  config.on_unauthenticated = ->(ctx : HTTP::Server::Context) do
    ctx.response.print "You must log in first."
  end

  config.on_unauthorized = ->(ctx : HTTP::Server::Context) do
    ctx.response.print "You do not have permission."
  end

  config.auth_rules << Kemal::Guardian::Rule.new(
    /^\/admin/,
    roles: ["admin"]
  )

  config.auth_rules << Kemal::Guardian::Rule.new(
    /^\//
  )

  config.authenticators << ->(ctx : HTTP::Server::Context) : Kemal::Guardian::Identity? do
    Kemal::Guardian::IdentityUser(Int32).new 1, Set(String).new(["admin"]) # remove roles to test `on_unauthorized`
  end
end

get "/" do
  "Hello World!"
end

get "/admin" do
  "Hello admin!"
end

Kemal.run
```

### How it works

kemal-guardian processes requests in this order:
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
my_special_auth = ->(ctx : HTTP::Server::Context) : Kemal::Guardian::Identity? do
  # your logic here
end

Kemal::Guardian::Rule.new(/^\/private/, roles: ["member"], authenticator: my_special_auth)
```

### Identity

kemal-guardian needs an identity type that represents the authenticated user.
Every identity must implement:

```crystal
abstract class Kemal::Guardian::Identity
  abstract def roles : Set(String)
end
```

kemal-guardian ships with a simple identity type:

```crystal
class Kemal::Guardian::IdentityUser(ID) < Kemal::Guardian::Identity
  getter id : ID
  getter roles : Set(String)
end
```

You can use any ID type (`Int32`, `String`, `UUID`, etc.).
To define your own identity type, inherit from `Identity`:

```crystal
class MyUser < Kemal::Guardian::Identity
  getter roles : Set(String)
  getter email : String
end
```

### Authenticator example

```crystal
config.authenticators << ->(ctx : HTTP::Server::Context) : Kemal::Guardian::Identity? do
  token = ctx.request.headers["Authorization"]?
  next nil unless token

  user = MyUserRepository.find_by_token(token)
  next nil unless user

  Kemal::Guardian::IdentityUser(Int32).new(user.id, Set{"admin"})
end
```

### Rules

A rule defines when and how kemal-guardian enforces authorization:

```crystal
Kemal::Guardian::Rule.new(
  path_regex : Regex,
  roles : Array(String) = [],
  methods : Array(String)? = nil,
  authenticator : Kemal::Guardian::Authenticator? = nil
)
```

- `path_regex`: matched against ctx.request.path
- `roles`: user must have at least one of these roles
- `methods`: optional HTTP method filter (GET/POST/PUT/DELETE/etc.)
- `authenticator`: optional override for this rule only

Rules are evaluated in the order they were added.
The first matching rule is used.

### ⚠️ Security Warning

kemal-guardian does not perform authentication.
It only consumes the identity returned by your authenticators and enforces authorization rules.
Make sure your authentication mechanism (sessions, tokens, cookies, etc.) is secure.

## Contributing

1. Fork it (<https://github.com/henrikac/kemal-guardian/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Henrik Christensen](https://github.com/henrikac) - creator and maintainer
