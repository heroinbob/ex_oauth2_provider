defmodule ExOauth2Provider.OpenId.OpenIdConfigTest do
  use ExUnit.Case, async: true

  alias ExOauth2Provider.OpenId.Claim
  alias ExOauth2Provider.OpenId.OpenIdConfig
  alias ExOauth2Provider.Test.Fixtures

  setup do
    config = Application.get_env(:ex_oauth2_provider, ExOauth2Provider)

    on_exit(fn ->
      Application.put_env(:ex_oauth2_provider, ExOauth2Provider, config)
    end)
  end

  describe "get/1" do
    test "returns a config struct" do
      assert OpenIdConfig.get([]) == %OpenIdConfig{claims: []}
    end

    test "returns the config with values pulled from the config" do
      Application.put_env(
        :ex_oauth2_provider,
        ExOauth2Provider,
        open_id: %{claims: [%{name: :fargo}]}
      )

      assert OpenIdConfig.get([]) == %OpenIdConfig{
               claims: [%Claim{name: :fargo}]
             }
    end

    test "returns the config with values pulled from the given config" do
      assert OpenIdConfig.get(
               open_id: %{
                 claims: [%{name: :override}]
               }
             ) == %OpenIdConfig{claims: [%Claim{name: :override}]}
    end
  end
end
