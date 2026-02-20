defmodule ExOauth2Provider.ScopesTest do
  use ExUnit.Case
  alias ExOauth2Provider.Scopes
  alias ExOauth2Provider.Test.Fixtures

  test "all?#true" do
    scopes = ["read", "write", "profile"]
    assert Scopes.all?(scopes, ["read", "profile"])
    assert Scopes.all?(scopes, ["write"])
    assert Scopes.all?(scopes, [])
  end

  test "all?#false" do
    scopes = ["read", "write", "profile"]
    refute Scopes.all?(scopes, ["read", "profile", "another_write"])
    refute Scopes.all?(scopes, ["read", "write", "profile", "another_write"])
  end

  test "equal?#true" do
    scopes = ["read", "write"]
    assert Scopes.equal?(scopes, ["read", "write"])
    assert Scopes.equal?(scopes, ["write", "read"])
  end

  test "equal?#false" do
    scopes = ["read", "write"]
    refute Scopes.equal?(scopes, ["read", "write", "profile"])
    refute Scopes.equal?(scopes, ["read"])
    refute Scopes.equal?(scopes, [])
  end

  test "to_string" do
    list = ["user:read", "user:write", "global_write"]
    assert Scopes.to_string(list) == "user:read user:write global_write"
  end

  describe "#from/1" do
    test "returns a list of scopes from any map with :scope that is a string" do
      assert Scopes.from(%{scope: "a b c"}) == ~w[a b c]
    end

    test "returns a list of scopes from any map with :scopes that is a string" do
      app = Fixtures.build(:application, scopes: "a b c")
      assert Scopes.from(app) == ~w[a b c]

      grant = Fixtures.build(:access_grant, scopes: "d e f")
      assert Scopes.from(grant) == ~w[d e f]

      assert Scopes.from(%{scopes: "x y z"}) == ~w[x y z]
    end

    test "returns a list of scopes from any map with \"scope\" that is a string" do
      assert Scopes.from(%{"scope" => "x y z"}) == ~w[x y z]
    end

    test "returns an empty list when given an unsupported value" do
      assert Scopes.from(%{"ta" => "da"}) == []
      assert Scopes.from(nil) == []
      assert Scopes.from("foo") == []
    end
  end

  describe "#to_list/1" do
    test "returns a list of the values when given a space separated string" do
      str = "user:read user:write global_write"
      assert Scopes.to_list(str) == ["user:read", "user:write", "global_write"]
      assert Scopes.to_list(nil) == []
    end
  end
end
