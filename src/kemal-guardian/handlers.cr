require "uri"

require "kemal"

module Kemal::Guardian
  class AuthHandler < Kemal::Handler
    def call(ctx)
      config = Kemal::Guardian.config
      auth_rules = config.auth_rules

      return call_next ctx if auth_rules.empty?

      matching_rule : Rule? = nil
      auth_rules.each do |rule|
        if rule.matches?(ctx)
          matching_rule = rule
          break
        end
      end

      return call_next ctx if matching_rule.nil?
      return call_next ctx if matching_rule.roles.empty?

      user = nil.as(Identity?)

      if matching_rule_authenticator = matching_rule.authenticator
        user = matching_rule_authenticator.call(ctx)
      else
        config.authenticators.each do |auth|
          if u = auth.call(ctx)
            user = u
            break
          end
        end
      end

      unless user
        ctx.response.status = HTTP::Status::UNAUTHORIZED
        config.on_unauthenticated.try &.call ctx
        return
      end

      identity = user.not_nil!

      matching_rule.roles.each do |role|
        if identity.roles.includes?(role)
          return call_next ctx
        end
      end

      ctx.response.status = HTTP::Status::FORBIDDEN
      config.on_unauthorized.try &.call ctx
    end
  end
end
