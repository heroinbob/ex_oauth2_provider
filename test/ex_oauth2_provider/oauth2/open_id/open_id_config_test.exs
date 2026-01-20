defmodule ExOauth2Provider.OpenId.OpenIdConfigTest do
  # Do not run tests async when doing config testing
  use ExUnit.Case, async: false
  use ExOauth2Provider.Test.ConfigChanges

  alias ExOauth2Provider.OpenId.Claim
  alias ExOauth2Provider.OpenId.OpenIdConfig

  @one_week 3600 * 24 * 7

  describe "get/1" do
    test "returns a config struct" do
      put_env_change(
        open_id: %{
          id_token_audience: "a",
          id_token_issuer: "i"
        }
      )

      assert OpenIdConfig.get([]) == %OpenIdConfig{
               claims: [],
               id_token_audience: "a",
               id_token_issuer: "i",
               id_token_lifespan: @one_week
             }
    end

    test "returns the config with values pulled from the app config" do
      put_env_change(
        open_id: %{
          claims: [%{name: :fargo}],
          id_token_audience: "x",
          id_token_issuer: "y"
        }
      )

      assert OpenIdConfig.get([]) == %OpenIdConfig{
               claims: [%Claim{name: :fargo}],
               id_token_audience: "x",
               id_token_issuer: "y"
             }
    end

    test "returns the config with values pulled from the given config" do
      assert OpenIdConfig.get(
               open_id: %{
                 claims: [%{name: :override}],
                 id_token_audience: "x",
                 id_token_issuer: "y",
                 id_token_lifespan: 42
               }
             ) == %OpenIdConfig{
               claims: [%Claim{name: :override}],
               id_token_audience: "x",
               id_token_issuer: "y",
               id_token_lifespan: 42
             }
    end

    test "throws out nil values in the config" do
      put_env_change(
        open_id: %{
          claims: nil,
          id_token_audience: "a",
          id_token_issuer: "i",
          id_token_lifespan: nil
        }
      )

      assert %OpenIdConfig{
               claims: [],
               id_token_lifespan: @one_week
             } = OpenIdConfig.get([])
    end
  end
end
