module Kemal::Guardian
  abstract class Identity
    abstract def roles : Set(String)
  end

  class IdentityUser(ID) < Identity
    getter id : ID
    getter roles : Set(String)

    def initialize(@id : ID, @roles : Set(String))
    end
  end
end