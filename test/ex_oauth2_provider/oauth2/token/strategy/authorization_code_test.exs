defmodule ExOauth2Provider.Token.Strategy.AuthorizationCodeTest do
  use ExOauth2Provider.TestCase

  alias Dummy.{
    OauthAccessTokens.OauthAccessToken,
    Repo
  }

  alias ExOauth2Provider.{
    Config,
    Token,
    Token.AuthorizationCode,
    AccessGrants
  }

  alias ExOauth2Provider.Test.{Fixtures, PKCE, QueryHelpers}

  @client_id "Jf5rM8hQBc"
  @client_secret "secret"
  @code "code"
  @redirect_uri "urn:ietf:wg:oauth:2.0:oob"

  @valid_request %{
    "client_id" => @client_id,
    "client_secret" => @client_secret,
    "code" => @code,
    "grant_type" => "authorization_code",
    "redirect_uri" => @redirect_uri
  }

  @invalid_client_error %{
    error: :invalid_client,
    error_description:
      "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
  }
  @invalid_grant %{
    error: :invalid_grant,
    error_description:
      "The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."
  }

  describe "#grant/2" do
    setup do
      resource_owner = Fixtures.insert(:user)

      application =
        Fixtures.insert(
          :application,
          uid: @client_id,
          secret: @client_secret
        )

      access_grant =
        Fixtures.insert(
          :access_grant,
          application: application,
          redirect_uri: @redirect_uri,
          resource_owner: resource_owner,
          token: @code
        )

      {
        :ok,
        %{
          resource_owner: resource_owner,
          application: application,
          access_grant: access_grant
        }
      }
    end

    test "creates and returns the access token", %{
      resource_owner: resource_owner,
      application: application,
      access_grant: access_grant
    } do
      assert {:ok, body} = Token.grant(@valid_request, otp_app: :ex_oauth2_provider)
      access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

      assert body.access_token == access_token.token
      assert access_token.resource_owner_id == resource_owner.id
      assert access_token.application_id == application.id
      assert access_token.scopes == access_grant.scopes

      assert access_token.expires_in ==
               Config.access_token_expires_in(otp_app: :ex_oauth2_provider)

      refute is_nil(access_token.refresh_token)
    end

    test "returns access token when client secret not required", %{
      resource_owner: resource_owner,
      application: application
    } do
      QueryHelpers.change!(application, secret: "")
      valid_request_no_client_secret = Map.drop(@valid_request, ["client_secret"])

      assert {:ok, body} =
               Token.grant(valid_request_no_client_secret, otp_app: :ex_oauth2_provider)

      access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

      assert body.access_token == access_token.token
      assert access_token.resource_owner_id == resource_owner.id
      assert access_token.application_id == application.id
    end

    test "returns returns access token with custom response handler" do
      assert {:ok, body} =
               AuthorizationCode.grant(@valid_request,
                 otp_app: :ex_oauth2_provider,
                 access_token_response_body_handler:
                   {__MODULE__, :access_token_response_body_handler}
               )

      access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

      assert body.custom_attr == access_token.inserted_at
    end

    test "doesn't set refresh_token when ExOauth2Provider.Config.use_refresh_token? == false" do
      assert {:ok, body} =
               AuthorizationCode.grant(@valid_request,
                 otp_app: :ex_oauth2_provider,
                 use_refresh_token: false
               )

      access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

      assert body.access_token == access_token.token
      assert is_nil(access_token.refresh_token)
    end

    test "can't use grant twice" do
      assert {:ok, _body} = Token.grant(@valid_request, otp_app: :ex_oauth2_provider)

      assert Token.grant(@valid_request, otp_app: :ex_oauth2_provider) ==
               {:error, @invalid_grant, :unprocessable_entity}
    end

    test "returns the existing access token when it is still valid", %{
      resource_owner: resource_owner,
      application: application
    } do
      assert {:ok, body} = Token.grant(@valid_request, otp_app: :ex_oauth2_provider)

      access_grant =
        Fixtures.insert(
          :access_grant,
          application: application,
          redirect_uri: @redirect_uri,
          resource_owner: resource_owner,
          token: "new_code"
        )

      valid_request = Map.merge(@valid_request, %{"code" => access_grant.token})
      assert {:ok, body2} = Token.grant(valid_request, otp_app: :ex_oauth2_provider)

      assert body.access_token == body2.access_token
    end

    test "returns error when invalid client" do
      request_invalid_client = Map.merge(@valid_request, %{"client_id" => "invalid"})

      assert Token.grant(request_invalid_client, otp_app: :ex_oauth2_provider) ==
               {:error, @invalid_client_error, :unprocessable_entity}
    end

    test "returns error when invalid secret" do
      request_invalid_client = Map.merge(@valid_request, %{"client_secret" => "invalid"})

      assert Token.grant(request_invalid_client, otp_app: :ex_oauth2_provider) ==
               {:error, @invalid_client_error, :unprocessable_entity}
    end

    test "returns error when invalid grant" do
      request_invalid_grant = Map.merge(@valid_request, %{"code" => "invalid"})

      assert Token.grant(request_invalid_grant, otp_app: :ex_oauth2_provider) ==
               {:error, @invalid_grant, :unprocessable_entity}
    end

    test "returns error when grant owned by another client", %{access_grant: access_grant} do
      new_application = Fixtures.insert(:application, uid: "new_app")
      QueryHelpers.change!(access_grant, application_id: new_application.id)

      assert Token.grant(@valid_request, otp_app: :ex_oauth2_provider) ==
               {:error, @invalid_grant, :unprocessable_entity}
    end

    test "returns error when revoked grant", %{access_grant: access_grant} do
      QueryHelpers.change!(access_grant, revoked_at: DateTime.utc_now())

      assert Token.grant(@valid_request, otp_app: :ex_oauth2_provider) ==
               {:error, @invalid_grant, :unprocessable_entity}
    end

    test "returns error when grant expired", %{access_grant: access_grant} do
      inserted_at =
        QueryHelpers.timestamp(OauthAccessToken, :inserted_at, seconds: -access_grant.expires_in)

      QueryHelpers.change!(access_grant, inserted_at: inserted_at)

      assert Token.grant(@valid_request, otp_app: :ex_oauth2_provider) ==
               {:error, @invalid_grant, :unprocessable_entity}
    end

    test "returns error when grant revoked", %{access_grant: access_grant} do
      AccessGrants.revoke(access_grant, otp_app: :ex_oauth2_provider)

      assert Token.grant(@valid_request, otp_app: :ex_oauth2_provider) ==
               {:error, @invalid_grant, :unprocessable_entity}
    end

    test "returns error when invalid redirect_uri" do
      request_invalid_redirect_uri = Map.merge(@valid_request, %{"redirect_uri" => "invalid"})

      assert Token.grant(request_invalid_redirect_uri, otp_app: :ex_oauth2_provider) ==
               {:error, @invalid_grant, :unprocessable_entity}
    end
  end

  describe "grant/3 when PKCE is enabled" do
    setup do
      resource_owner = Fixtures.insert(:user)

      application =
        Fixtures.insert(
          :application,
          uid: @client_id,
          secret: @client_secret
        )

      access_grant =
        Fixtures.insert(
          :access_grant,
          application: application,
          redirect_uri: @redirect_uri,
          resource_owner: resource_owner,
          token: @code
        )

      {
        :ok,
        %{
          resource_owner: resource_owner,
          application: application,
          access_grant: access_grant
        }
      }
    end

    test "validates the PKCE info and returns the grant", %{access_grant: access_grant} do
      verifier = PKCE.generate_code_verifier()
      challenge = PKCE.generate_code_challenge(verifier, :s256)

      # The verifier is passed in the request. It's used to compare against
      # the challenge that was used for the access grant.
      request = Map.put(@valid_request, "code_verifier", verifier)

      # Store the challenge on the grant so we can compare.
      access_grant
      |> Ecto.Changeset.cast(
        %{code_challenge: challenge, code_challenge_method: :s256},
        [:code_challenge, :code_challenge_method]
      )
      |> Repo.update!()

      assert {:ok, %{access_token: _}} =
               Token.grant(request, otp_app: :ex_oauth2_provider, pkce: :all_methods)
    end

    test "returns an error when the PKCE info is invalid" do
      verifier = PKCE.generate_code_verifier()

      request = Map.put(@valid_request, "code_verifier", verifier)

      assert Token.grant(request, otp_app: :ex_oauth2_provider, pkce: :all_methods) ==
               {:error, @invalid_grant, :unprocessable_entity}
    end
  end

  describe "grant/3 when request is for an OpenID token" do
    setup do
      application =
        Fixtures.insert(
          :application,
          secret: @client_secret,
          scopes: "openid read write",
          uid: @client_id
        )

      %{resource_owner: owner} =
        access_grant =
        Fixtures.insert(
          :access_grant,
          application: application,
          open_id_nonce: "abc123",
          redirect_uri: @redirect_uri,
          scopes: application.scopes,
          token: @code
        )

      {
        :ok,
        %{
          resource_owner: owner,
          application: application,
          access_grant: access_grant
        }
      }
    end

    test "creates and returns the access token and ID token" do
      assert {
               :ok,
               %{access_token: _, id_token: _}
             } = Token.grant(@valid_request, otp_app: :ex_oauth2_provider)
    end

    test "returns the existing tokens when valid", %{
      resource_owner: resource_owner,
      application: application
    } do
      %{token: existing_token} =
        Fixtures.insert(
          :access_token,
          application: application,
          resource_owner: resource_owner,
          scopes: application.scopes
        )

      assert {
               :ok,
               %{access_token: %{access_token: ^existing_token}, id_token: _}
             } = Token.grant(@valid_request, otp_app: :ex_oauth2_provider)
    end
  end

  def access_token_response_body_handler(body, access_token) do
    Map.merge(body, %{custom_attr: access_token.inserted_at})
  end
end
