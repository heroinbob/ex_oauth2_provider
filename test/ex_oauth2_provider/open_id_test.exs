defmodule ExOauth2Provider.OpenIdTest do
  # No async - these tests perform config changes
  use ExOauth2Provider.TestCase, async: false
  use ExOauth2Provider.Test.ConfigChanges

  alias ExOauth2Provider.OpenId
  alias ExOauth2Provider.Test.Fixtures

  @unix_epoch ~N[1970-01-01 00:00:00]

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

      assert %{email: ^email} =
               OpenId.generate_id_token(
                 token,
                 context,
                 open_id: %{
                   claims: [%{name: :email}],
                   id_token_audience: "aud",
                   id_token_issuer: "iss"
                 }
               )
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
end
