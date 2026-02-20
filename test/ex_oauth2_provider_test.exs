defmodule ExOauth2ProviderTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  alias ExOauth2Provider.AccessTokens
  alias ExOauth2Provider.Test.Fixtures
  alias ExOauth2Provider.Test.OpenId
  alias ExOauth2Provider.Utils
  alias Dummy.{OauthAccessTokens.OauthAccessToken, Repo}

  describe "authenticate_token/2" do
    test "error when invalid" do
      assert ExOauth2Provider.authenticate_token(nil, otp_app: :ex_oauth2_provider) ==
               {:error, :token_inaccessible}

      assert ExOauth2Provider.authenticate_token("secret", otp_app: :ex_oauth2_provider) ==
               {:error, :token_not_found}
    end

    test "authenticates with a non application token" do
      access_token = Fixtures.insert(:access_token, application: nil)

      assert {:ok, %OauthAccessToken{id: id, resource_owner: resource_owner}} =
               ExOauth2Provider.authenticate_token(
                 access_token.token,
                 otp_app: :ex_oauth2_provider
               )

      assert id == access_token.id
      assert resource_owner
    end

    test "preloads the resource owner when not loaded" do
      %{id: user_id} = Fixtures.insert(:user)

      access_token =
        Fixtures.insert(
          :access_token,
          application: nil,
          resource_owner: nil,
          resource_owner_id: user_id
        )

      assert {:ok, %OauthAccessToken{resource_owner: %{id: ^user_id}}} =
               ExOauth2Provider.authenticate_token(
                 access_token.token,
                 otp_app: :ex_oauth2_provider
               )
    end

    test "authenticates with application-wide token" do
      # Factory creates an application by default.
      # Application access tokens don't have a resource owner though.
      access_token = Fixtures.insert(:access_token)

      assert {:ok, %OauthAccessToken{id: id}} =
               ExOauth2Provider.authenticate_token(access_token.token,
                 otp_app: :ex_oauth2_provider
               )

      assert id == access_token.id
    end

    test "revokes previous refresh token" do
      %{application: app, resource_owner: user} =
        access_token = Fixtures.insert(:access_token, refresh_token: Utils.generate_token())

      access_token2 =
        Fixtures.insert(
          :access_token,
          application: app,
          previous_refresh_token: access_token.refresh_token,
          refresh_token: Utils.generate_token(),
          resource_owner: user
        )

      assert {:ok, access_token} =
               ExOauth2Provider.authenticate_token(access_token.token,
                 otp_app: :ex_oauth2_provider
               )

      access_token = Repo.get_by(OauthAccessToken, token: access_token.token)
      refute AccessTokens.is_revoked?(access_token)
      access_token2 = Repo.get_by(OauthAccessToken, token: access_token2.token)
      refute "" == access_token2.previous_refresh_token

      assert {:ok, access_token2} =
               ExOauth2Provider.authenticate_token(access_token2.token,
                 otp_app: :ex_oauth2_provider
               )

      access_token = Repo.get_by(OauthAccessToken, token: access_token.token)
      assert AccessTokens.is_revoked?(access_token)
      access_token2 = Repo.get_by(OauthAccessToken, token: access_token2.token)
      assert "" == access_token2.previous_refresh_token
    end

    test "doesn't revoke when refresh_token_revoked_on_use? == false" do
      user = Fixtures.insert(:user)

      access_token =
        Fixtures.insert(
          :access_token,
          refresh_token: Utils.generate_token(),
          resource_owner: user
        )

      access_token2 =
        Fixtures.insert(
          :access_token,
          refresh_token: Utils.generate_token(),
          resource_owner: user,
          previous_refresh_token: access_token.token
        )

      assert {:ok, access_token2} =
               ExOauth2Provider.authenticate_token(access_token2.token,
                 otp_app: :ex_oauth2_provider,
                 revoke_refresh_token_on_use: false
               )

      access_token = Repo.get_by(OauthAccessToken, token: access_token.token)
      refute AccessTokens.is_revoked?(access_token)
      access_token2 = Repo.get_by(OauthAccessToken, token: access_token2.token)
      refute "" == access_token2.previous_refresh_token
    end

    test "error when expired token" do
      access_token = Fixtures.insert(:access_token, expires_in: -1)

      assert ExOauth2Provider.authenticate_token(access_token.token, otp_app: :ex_oauth2_provider) ==
               {:error, :token_inaccessible}
    end

    test "error when revoked token" do
      access_token = Fixtures.insert(:access_token)
      AccessTokens.revoke(access_token)

      assert ExOauth2Provider.authenticate_token(access_token.token, otp_app: :ex_oauth2_provider) ==
               {:error, :token_inaccessible}
    end
  end

  describe "end_session/2" do
    test "returns the result of the call with the given params" do
      app = Fixtures.insert(:application, scopes: "openid")
      %{resource_owner: user} = Fixtures.insert(:access_token, application: app)
      hint = OpenId.generate_signed_id_token(app, user)
      params = %{"id_token_hint" => hint, "user_id" => user.id}

      assert ExOauth2Provider.end_session(params, otp_app: :ex_oauth2_provider) == :ok
    end
  end
end
