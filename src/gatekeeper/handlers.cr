require "http/server/handler"

module Gatekeeper
  class AuthHandler
    include HTTP::Handler

    def call(context)
      config = Gatekeeper.config
      auth_rules = config.auth_rules

      return call_next context if auth_rules.empty?

      matching_rule : Rule? = nil
      auth_rules.each do |rule|
        if rule.matches?(context)
          matching_rule = rule
          break
        end
      end

      return call_next context if matching_rule.nil?
      return call_next context if matching_rule.roles.empty?

      user = nil.as(Identity?)

      if matching_rule_authenticator = matching_rule.authenticator
        user = matching_rule_authenticator.call(context)
      else
        config.authenticators.each do |auth|
          if u = auth.call(context)
            user = u
            break
          end
        end
      end

      unless user
        context.response.status = HTTP::Status::UNAUTHORIZED
        config.on_unauthenticated.try &.call context
        return
      end

      identity = user.not_nil!

      matching_rule.roles.each do |role|
        if identity.roles.includes?(role)
          return call_next context
        end
      end

      context.response.status = HTTP::Status::FORBIDDEN
      config.on_unauthorized.try &.call context
    end
  end
end
