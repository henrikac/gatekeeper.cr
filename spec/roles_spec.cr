require "./spec_helper"

describe Gatekeeper::Roles do
  it "expands roles with direct children from hierarchy" do
    base_roles = Set{"ROLE_ADMIN"}
    hierarchy = {
      "ROLE_ADMIN" => ["ROLE_USER", "ROLE_READER"],
    } of String => Array(String)

    result = Gatekeeper::Roles.expand(base_roles, hierarchy)

    result.includes?("ROLE_ADMIN").should be_true
    result.includes?("ROLE_USER").should be_true
    result.includes?("ROLE_READER").should be_true
    result.size.should eq 3
  end

  it "expands roles transitively through hierarchy" do
    base_roles = Set{"ROLE_ADMIN"}
    hierarchy = {
      "ROLE_ADMIN" => ["ROLE_USER"],
      "ROLE_USER"  => ["ROLE_READER"],
    } of String => Array(String)

    result = Gatekeeper::Roles.expand(base_roles, hierarchy)

    result.includes?("ROLE_ADMIN").should be_true
    result.includes?("ROLE_USER").should be_true
    result.includes?("ROLE_READER").should be_true
    result.size.should eq 3
  end

  it "handles cycles in hierarchy without infinite loop" do
    base_roles = Set{"ROLE_A"}
    hierarchy = {
      "ROLE_A" => ["ROLE_B"],
      "ROLE_B" => ["ROLE_A"],
    } of String => Array(String)

    result = Gatekeeper::Roles.expand(base_roles, hierarchy)

    result.includes?("ROLE_A").should be_true
    result.includes?("ROLE_B").should be_true
    result.size.should eq 2
  end

  it "role_satisfied? returns true when effective roles contain at least one required role" do
    identity_roles = Set{"ROLE_ADMIN"}
    required_roles = ["ROLE_USER"]
    hierarchy = {
      "ROLE_ADMIN" => ["ROLE_USER"],
    } of String => Array(String)

    Gatekeeper::Roles.satisfied?(identity_roles, required_roles, hierarchy).should be_true
  end

  it "role_satisfied? returns false when hierarchy does not provide required role" do
    identity_roles = Set{"ROLE_ADMIN"}
    required_roles = ["ROLE_SUPERUSER"]
    hierarchy = {
      "ROLE_ADMIN" => ["ROLE_USER"],
    } of String => Array(String)

    Gatekeeper::Roles.satisfied?(identity_roles, required_roles, hierarchy).should be_false
  end

  it "role_satisfied? behaves like simple includes? when hierarchy is empty" do
    identity_roles = Set{"ROLE_ADMIN"}
    required_roles = ["ROLE_USER"]
    hierarchy = {} of String => Array(String)

    Gatekeeper::Roles.satisfied?(identity_roles, required_roles, hierarchy).should be_false
  end
end
