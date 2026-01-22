defmodule ExOauth2Provider.OpenIdTest do
  # No async - these tests perform config changes
  use ExOauth2Provider.TestCase, async: false
  use ExOauth2Provider.Test.ConfigChanges

  alias ExOauth2Provider.OpenId
  alias ExOauth2Provider.OpenId.Errors.SigningError
  alias ExOauth2Provider.Test.Fixtures

  defdelegate get_open_id_config(), to: ExOauth2Provider.Test.OpenId, as: :get_config
  defdelegate signed_jwt?(value, algorithm, jwt), to: ExOauth2Provider.Test.OpenId
  defdelegate signed_jwt?(value, algorithm, jwt, key_id), to: ExOauth2Provider.Test.OpenId

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
      original_config = get_open_id_config()

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

  describe "sign_id_token!/1" do
    test "returns a signed, compact JWS for the given claims map" do
      %{
        id_token_signing_key_algorithm: signing_algorithm,
        id_token_signing_key_id: key_id
      } = get_open_id_config()

      signed = OpenId.sign_id_token!(%{aud: "foo", iss: "bar"})

      assert signed_jwt?(
               signed,
               signing_algorithm,
               %{"aud" => "foo", "iss" => "bar"},
               key_id
             )
    end

    test "raises an error when the ID token can't be signed" do
      # Force an error by providing a bad algorithm
      add_open_id_changes(%{id_token_signing_key_algorithm: "haha"})

      assert_raise(SigningError, fn ->
        OpenId.sign_id_token!(%{iss: "space station"})
      end)
    end

    test "does not add key id when it is not defined/supported" do
      %{id_token_signing_key_algorithm: signing_algorithm} = get_open_id_config()
      add_open_id_changes(%{id_token_signing_key_id: nil})

      signed = OpenId.sign_id_token!(%{iss: "station"})

      assert signed_jwt?(
               signed,
               signing_algorithm,
               %{"iss" => "station"}
             )
    end
  end

  describe "sign_id_token!/2" do
    test "allows overriding the app config" do
      %{id_token_signing_key_algorithm: signing_algorithm} =
        original_config = get_open_id_config()

      opts = [open_id: Map.put(original_config, :id_token_signing_key_id, "abc123")]
      signed = OpenId.sign_id_token!(%{iss: "me"}, opts)

      assert signed_jwt?(
               signed,
               signing_algorithm,
               %{"iss" => "me"},
               "abc123"
             )
    end
  end
end
