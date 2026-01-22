defmodule ExOauth2Provider.OpenIdTest do
  # No async - these tests perform config changes
  use ExOauth2Provider.TestCase, async: false
  use ExOauth2Provider.Test.ConfigChanges

  alias ExOauth2Provider.OpenId
  alias ExOauth2Provider.Test.Fixtures

  describe "fetch_nonce/1" do
    test "returns the nonce when it's present in the request" do
      nonce = "foo"

      assert OpenId.fetch_nonce(%{"nonce" => nonce}) == {:ok, nonce}
    end

    test "returns nil when it's not present in the request" do
      assert OpenId.fetch_nonce(%{"fake" => 123}) == :not_found
    end
  end

  describe "generate_id_token/3" do
    test "returns the ID token for the given info" do
      app = Fixtures.insert(:application)
      %{resource_owner: %{id: user_id}} = token = Fixtures.insert(:access_token, application: app)
      grant = Fixtures.insert(:access_grant, application: app)
      context = %{access_grant: grant, client: app}

      assert %{sub: ^user_id} = OpenId.generate_id_token(token, context, [])
    end

    test "passes the given config for open_id" do
      original_config =
        :ex_oauth2_provider
        |> Application.get_env(ExOauth2Provider)
        |> Keyword.fetch!(:open_id)

      custom_config =
        Map.merge(
          original_config,
          %{
            claims: [%{name: :email}],
            id_token_audience: "aud",
            id_token_issuer: "iss"
          }
        )

      %{email: email} = user = Fixtures.insert(:user)
      app = Fixtures.insert(:application)

      token =
        Fixtures.insert(
          :access_token,
          application: app,
          resource_owner: user,
          scopes: "openid email"
        )

      grant = Fixtures.insert(:access_grant, application: app)

      context = %{access_grant: grant, client: app}

      assert %{email: ^email} = OpenId.generate_id_token(token, context, open_id: custom_config)
    end
  end

  describe "in_scope?/1" do
    test "returns true when given a string that has openid in it" do
      assert OpenId.in_scope?("write openid test") == true
      assert OpenId.in_scope?("openid") == true
      assert OpenId.in_scope?("openid test") == true
    end

    test "returns false when given a string without openid in it" do
      assert OpenId.in_scope?("write test") == false
    end

    test "returns true when given a list that has openid in it" do
      assert OpenId.in_scope?(~w[openid test write]) == true
      assert OpenId.in_scope?(~w[test openid write]) == true
      assert OpenId.in_scope?(~w[openid]) == true
    end

    test "returns false when given a list without openid in it" do
      assert OpenId.in_scope?(~w[test write]) == false
    end

    test "returns false when given an unsupported type" do
      assert OpenId.in_scope?(nil) == false
    end
  end

  describe "sign_token/1" do
    test "returns a signed, compact JWS for the given claims map" do
      # This is built using the existing config... so this is an RS256 key.
      private_key = Fixtures.build(:private_rs256_key)

      %{
        id_token_signing_key_algorithm: signing_algorithm,
        id_token_signing_key_id: key_id
      } =
        :ex_oauth2_provider
        |> Application.get_env(ExOauth2Provider)
        |> Keyword.fetch!(:open_id)

      claims = %{aud: "foo", iss: "bar"}

      assert {:ok, jws} = OpenId.sign_id_token(claims)
      assert is_binary(jws)

      assert {
               true = _is_valid,
               %JOSE.JWT{fields: %{"aud" => "foo", "iss" => "bar"}},
               %JOSE.JWS{
                 alg: {_, :RS256},
                 fields: %{"kid" => ^key_id, "typ" => "JWT"}
               }
             } = JOSE.JWT.verify_strict(private_key, [signing_algorithm], jws)
    end

    test "returns an error when the ID token can't be signed" do
      # Force an error by providing a bad algorithm
      add_open_id_changes(%{id_token_signing_key_algorithm: "haha"})

      assert {:error, %FunctionClauseError{module: :jose_jws}} =
               OpenId.sign_id_token(%{iss: "space station"})
    end

    test "does not add key id when it is not defined/supported" do
      private_key = Fixtures.build(:private_rs256_key)

      %{id_token_signing_key_algorithm: signing_algorithm} =
        :ex_oauth2_provider
        |> Application.get_env(ExOauth2Provider)
        |> Keyword.fetch!(:open_id)

      add_open_id_changes(%{id_token_signing_key_id: nil})

      assert {:ok, jws} = OpenId.sign_id_token(%{iss: "station"})

      assert {
               true = _is_valid,
               _jwt,
               %JOSE.JWS{fields: fields}
             } = JOSE.JWT.verify_strict(private_key, [signing_algorithm], jws)

      assert fields == %{"typ" => "JWT"}
    end
  end

  describe "sign_token/2" do
    test "allows overriding the app config" do
      private_key = Fixtures.build(:private_rs256_key)

      %{id_token_signing_key_algorithm: signing_algorithm} =
        original_config =
        :ex_oauth2_provider
        |> Application.get_env(ExOauth2Provider)
        |> Keyword.fetch!(:open_id)

      opts = [open_id: Map.put(original_config, :id_token_signing_key_id, "abc123")]

      assert {:ok, jws} = OpenId.sign_id_token(%{iss: "me"}, opts)

      assert {
               true = _is_valid,
               _jwt,
               %JOSE.JWS{fields: %{"kid" => "abc123"}}
             } = JOSE.JWT.verify_strict(private_key, [signing_algorithm], jws)
    end
  end
end
