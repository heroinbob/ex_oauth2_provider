defmodule ExOauth2Provider.OpenId.OpenIdConfigTest do
  # Do not run tests async when doing config testing
  use ExUnit.Case, async: false
  use ExOauth2Provider.Test.ConfigChanges

  alias ExOauth2Provider.OpenId.Claim
  alias ExOauth2Provider.OpenId.OpenIdConfig
  alias ExOauth2Provider.Test.Fixtures
  alias ExOauth2Provider.Test.OpenId

  @one_week 3600 * 24 * 7

  describe "get/1" do
    test "returns a config struct" do
      # This is grabbed using the PEM in the config
      signing_key = Fixtures.build(:private_rs256_key)

      %{
        id_token_audience: aud,
        id_token_issuer: iss,
        id_token_signing_key_algorithm: algorithm,
        id_token_signing_key_id: key_id
      } = OpenId.get_config()

      assert OpenIdConfig.get([]) == %OpenIdConfig{
               claims: [],
               id_token_audience: aud,
               id_token_issuer: iss,
               id_token_lifespan: @one_week,
               id_token_signing_key: signing_key,
               id_token_signing_key_algorithm: algorithm,
               id_token_signing_key_id: key_id
             }
    end

    test "returns the config with values pulled from the given config" do
      original_config = OpenId.get_config()

      changed_config =
        Map.merge(
          original_config,
          %{
            claims: [%{name: :override}],
            id_token_audience: "x",
            id_token_issuer: "y",
            id_token_lifespan: 42
          }
        )

      assert %OpenIdConfig{
               claims: [%Claim{name: :override}],
               id_token_audience: "x",
               id_token_issuer: "y",
               id_token_lifespan: 42
             } = OpenIdConfig.get(open_id: changed_config)
    end

    test "throws out nil values in the config" do
      add_open_id_changes(%{
        claims: nil,
        id_token_audience: "a",
        id_token_issuer: "i",
        id_token_lifespan: nil
      })

      assert %OpenIdConfig{
               claims: [],
               id_token_lifespan: @one_week
             } = OpenIdConfig.get([])
    end
  end
end
