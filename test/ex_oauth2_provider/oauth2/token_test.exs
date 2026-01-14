defmodule ExOauth2Provider.TokenTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Token
  alias ExOauth2Provider.Test.Fixtures
  alias ExOauth2Provider.Test.PKCE

  @client_id "Jf5rM8hQBc"
  @client_secret "secret"

  describe "#grant/2" do
    test "#returns an error when invalid grant_type" do
      assert {
               :error,
               %{
                 error: :unsupported_grant_type,
                 error_description: description
               },
               :unprocessable_entity
             } =
               Token.grant(
                 %{
                   "client_id" => @client_id,
                   "client_secret" => @client_secret,
                   "grant_type" => "invalid"
                 },
                 otp_app: :ex_oauth2_provider
               )

      assert description =~ ~r/grant type is not supported/i
    end

    test "#returns an error when grant_type is missing" do
      assert {
               :error,
               %{
                 error: :invalid_request,
                 error_description: description
               },
               :bad_request
             } =
               Token.grant(
                 %{
                   "client_id" => @client_id,
                   "client_secret" => @client_secret
                 },
                 otp_app: :ex_oauth2_provider
               )

      assert description =~ ~r/the request is missing a required/i
    end
  end

  describe "#grant/2 when grant_type is authorization_code" do
    test "returns the response of AuthorizationCode.grant/2 when valid" do
      %{owner: user} = application = Fixtures.insert(:application)

      Fixtures.access_grant(
        application,
        user,
        "ima-token",
        application.redirect_uri
      )

      assert {
               :ok,
               %{
                 access_token: _,
                 created_at: _,
                 expires_in: _,
                 refresh_token: _,
                 scope: "read",
                 token_type: "bearer"
               }
             } =
               Token.grant(
                 %{
                   "client_id" => application.uid,
                   "client_secret" => application.secret,
                   "code" => "ima-token",
                   "grant_type" => "authorization_code",
                   "redirect_uri" => application.redirect_uri
                 },
                 otp_app: :ex_oauth2_provider
               )
    end

    test "returns validation errors that AuthorizationCode.grant/2 returns" do
      application = Fixtures.insert(:application)

      assert {:error, %{error: :invalid_grant}, :unprocessable_entity} =
               Token.grant(
                 %{
                   "client_id" => application.uid,
                   "client_secret" => application.secret,
                   "code" => "ima-token",
                   "grant_type" => "authorization_code",
                   "redirect_uri" => application.redirect_uri
                 },
                 otp_app: :ex_oauth2_provider
               )
    end

    test "supports PKCE" do
      verifier = PKCE.generate_code_verifier()
      challenge = PKCE.generate_code_challenge(verifier, :s256)
      %{owner: user} = application = Fixtures.insert(:application)

      config = [
        otp_app: :ex_oauth2_provider,
        pkce: :all_methods
      ]

      Fixtures.access_grant(
        application,
        user,
        "ima-token",
        application.redirect_uri,
        code_challenge: challenge,
        code_challenge_method: :s256
      )

      payload = %{
        "client_id" => application.uid,
        "client_secret" => application.secret,
        "code" => "ima-token",
        "code_verifier" => verifier,
        "grant_type" => "authorization_code",
        "redirect_uri" => application.redirect_uri
      }

      assert {:ok, _access_token} = Token.grant(payload, config)

      # Insert another grant that's not revoked so we can test again with bad PKCE data.
      Fixtures.access_grant(
        application,
        user,
        "ima-different-token",
        application.redirect_uri,
        code_challenge: challenge,
        code_challenge_method: :s256
      )

      # RFC states invalid grant error must be returned on bad PKCE challenge
      assert {:error, %{error: :invalid_grant}, :unprocessable_entity} =
               payload
               |> Map.merge(%{
                 "code" => "ima-different-token",
                 "code_verifier" => "bad-verifier"
               })
               |> Token.grant(config)
    end

    test "returns the access token and id token when OpenID is enabled" do
      application = Fixtures.insert(:application, scopes: "openid")

      grant =
        Fixtures.insert(
          :access_grant,
          application: application,
          resource_owner: application.owner,
          redirect_uri: application.redirect_uri,
          scopes: application.scopes
        )

      payload = %{
        "client_id" => application.uid,
        "client_secret" => application.secret,
        "code" => grant.token,
        "grant_type" => "authorization_code",
        "redirect_uri" => application.redirect_uri
      }

      assert {
               :ok,
               %{access_token: _, id_token: _}
             } = Token.grant(payload, otp_app: :ex_oauth2_provider)
    end
  end
end
