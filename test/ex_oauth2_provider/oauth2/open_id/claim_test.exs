defmodule ExOauth2Provider.OpenId.ClaimTest do
  use ExUnit.Case, async: true

  alias ExOauth2Provider.OpenId.Claim
  alias ExOauth2Provider.Test.Fixtures

  describe "get_value_for/2" do
    test "returns the value for the claim from the source" do
      source = %{united_states_of: :whatever}
      claim = Fixtures.build(:open_id_claim, name: :united_states_of)

      assert Claim.get_value_for(claim, source) == :whatever
    end

    test "relies on the alias when defined" do
      source = %{yuk: :dum}

      claim =
        Fixtures.build(
          :open_id_claim,
          alias: :yuk,
          name: :fail
        )

      assert Claim.get_value_for(claim, source) == :dum
    end
  end

  describe "new/1" do
    test "returns a claim from the given map" do
      assert Claim.new(%{name: :foo}) == %Claim{
               alias: nil,
               includes: [],
               name: :foo
             }

      assert Claim.new(%{alias: :baz, name: :foo}) == %Claim{alias: :baz, name: :foo}

      assert Claim.new(%{
               includes: [%{name: :nested}],
               name: :foo
             }) == %Claim{
               name: :foo,
               includes: [
                 %Claim{name: :nested}
               ]
             }
    end
  end
end
