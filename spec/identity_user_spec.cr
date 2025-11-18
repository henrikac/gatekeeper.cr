require "./spec_helper"

describe Kemal::Guardian::IdentityUser do
  it "stores id and roles for string id" do
    roles = Set{"ROLE_USER", "ROLE_ADMIN"}
    user = Kemal::Guardian::IdentityUser(String).new("u1", roles)

    user.id.should eq "u1"
    user.roles.should eq roles
  end

  it "stores id and roles for int id" do
    roles = Set{"ROLE_USER"}
    user = Kemal::Guardian::IdentityUser(Int32).new(42, roles)

    user.id.should eq 42
    user.roles.should eq roles
  end

  it "is a kind of Identity" do
    roles = Set{"ROLE_USER"}
    user = Kemal::Guardian::IdentityUser(Int32).new(1, roles)

    user.should be_a Kemal::Guardian::Identity
    user.roles.should eq roles
  end
end
