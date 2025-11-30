module Gatekeeper
  module Roles
    def self.expand(base_roles : Set(String), hierarchy : Hash(String, Array(String))) : Set(String)
      result = base_roles.dup
      stack = base_roles.to_a

      while role = stack.pop?
        if children = hierarchy[role]?
          children.each do |child|
            unless result.includes?(child)
              result.add(child)
              stack << child
            end
          end
        end
      end

      result
    end

    def self.satisfied?(
      identity_roles : Set(String),
      required_roles : Array(String),
      hierarchy : Hash(String, Array(String))
    ) : Bool
      effective_roles =
        if hierarchy.empty?
          identity_roles
        else
          expand(identity_roles, hierarchy)
        end

      required_roles.any? { |role| effective_roles.includes?(role) }
    end
  end
end
