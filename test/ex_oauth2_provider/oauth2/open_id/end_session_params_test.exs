defmodule ExOauth2Provider.OpenId.EndSessionParamsTest do
  use ExOauth2Provider.TestCase, async: true

  alias Dummy.OauthApplications.OauthApplication
  alias ExOauth2Provider.OpenId.EndSessionParams
  alias ExOauth2Provider.Test.Fixtures
  alias ExOauth2Provider.Test.OpenId

  @opts otp_app: :ex_oauth2_provider

  describe "parse_request_params/2" do
    test "returns a map with the correct context for processing" do
      %{id: app_id} = app = Fixtures.insert(:application, scopes: "openid")
      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)

      id_token =
        Fixtures.build(
          :id_token,
          aud: app.uid,
          iss: config.id_token_issuer,
          sub: user_id
        )

      hint = OpenId.sign_id_token(id_token, config)
      params = %{"id_token_hint" => hint, "user_id" => user_id}

      assert {
               :ok,
               %EndSessionParams{
                 app: %OauthApplication{id: ^app_id},
                 id_token: ^id_token,
                 id_token_hint: ^hint,
                 post_logout_redirect_uri: nil,
                 user_id: ^user_id,
                 state: nil
               }
             } = EndSessionParams.parse_request_params(params, config, @opts)
    end

    test "returns the params when post_logout_redirect_uri is given and valid" do
      redirect_uri = "https://test.site/callback/abc123"

      app =
        Fixtures.insert(
          :application,
          open_id_post_logout_redirect_uri: redirect_uri,
          scopes: "openid"
        )

      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)

      id_token =
        Fixtures.build(
          :id_token,
          aud: app.uid,
          iss: config.id_token_issuer,
          sub: user_id
        )

      hint = OpenId.sign_id_token(id_token, config)

      params = %{
        "id_token_hint" => hint,
        "post_logout_redirect_uri" => redirect_uri,
        "user_id" => user_id
      }

      assert {
               :ok,
               %EndSessionParams{
                 post_logout_redirect_uri: ^redirect_uri
               }
             } = EndSessionParams.parse_request_params(params, config, @opts)
    end

    test "supports apps with multiple logout uris" do
      redirect_uri = "https://test.site/callback/abc123"

      app =
        Fixtures.insert(
          :application,
          open_id_post_logout_redirect_uri: "https://not-the-url.com/callback #{redirect_uri}",
          scopes: "openid"
        )

      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)

      hint =
        :id_token
        |> Fixtures.build(
          aud: app.uid,
          iss: config.id_token_issuer,
          sub: user_id
        )
        |> OpenId.sign_id_token(config)

      params = %{
        "id_token_hint" => hint,
        "post_logout_redirect_uri" => redirect_uri,
        "user_id" => user_id
      }

      assert {
               :ok,
               %EndSessionParams{
                 post_logout_redirect_uri: ^redirect_uri
               }
             } = EndSessionParams.parse_request_params(params, config, @opts)
    end

    test "returns the state when valid" do
      state = "7def8742-ea79-46b8-aa52-eb09e558885b"
      app = Fixtures.insert(:application, scopes: "openid")
      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)

      id_token =
        Fixtures.build(
          :id_token,
          aud: app.uid,
          iss: config.id_token_issuer,
          sub: user_id
        )

      hint = OpenId.sign_id_token(id_token, config)

      params = %{
        "id_token_hint" => hint,
        "user_id" => user_id,
        "state" => state
      }

      assert {
               :ok,
               %EndSessionParams{
                 state: ^state
               }
             } = EndSessionParams.parse_request_params(params, config, @opts)
    end

    test "returns an error when id_token_hint is missing" do
      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)
      params = %{"user_id" => user_id}

      assert {:error, %{id_token_hint: ["can't be blank"]}} =
               EndSessionParams.parse_request_params(params, config, @opts)

      params = %{"id_token_hint" => nil, "user_id" => user_id}

      assert {:error, %{id_token_hint: ["can't be blank"]}} =
               EndSessionParams.parse_request_params(params, config, @opts)

      params = %{"id_token_hint" => "", "user_id" => user_id}

      assert {:error, %{id_token_hint: ["can't be blank"]}} =
               EndSessionParams.parse_request_params(params, config, @opts)
    end

    test "returns an error when id_token_hint is the wrong type" do
      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)
      params = %{"id_token_hint" => %{"good" => "thing"}, "user_id" => user_id}

      assert {:error, %{id_token_hint: ["is invalid"]}} =
               EndSessionParams.parse_request_params(params, config, @opts)
    end

    test "returns an error when id_token_hint can't be verified" do
      %{id: user_id} = Fixtures.build_with_id(:user)
      id_token = Fixtures.build(:id_token)
      config = Fixtures.build(:config)

      # Sign with the key but make sure it's not part of the actual config that's passed
      # in. This way the verification is done the key in the config.
      custom_key = OpenId.generate_private_key()
      hint = OpenId.sign_id_token(id_token, %{config | id_token_signing_key: custom_key})
      params = %{"id_token_hint" => hint, "user_id" => user_id}

      assert {:error, %{id_token_hint: ["is invalid"]}} =
               EndSessionParams.parse_request_params(params, config, @opts)
    end

    test "returns an error when the aud attribute is invalid" do
      Fixtures.insert(
        :application,
        open_id_post_logout_redirect_uri: "https://test.com/callback/logout",
        scopes: "openid"
      )

      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)

      id_token =
        Fixtures.build(
          :id_token,
          aud: "not-the-app-uid",
          iss: config.id_token_issuer,
          sub: user_id
        )

      hint = OpenId.sign_id_token(id_token, config)
      params = %{"id_token_hint" => hint, "user_id" => user_id}

      assert EndSessionParams.parse_request_params(params, config, @opts) ==
               {:error, %{aud: ["is invalid"]}}
    end

    test "returns an error when the issuer is invalid" do
      app = Fixtures.insert(:application, scopes: "openid")
      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)

      id_token =
        Fixtures.build(
          :id_token,
          aud: app.uid,
          iss: "not-the-issuer",
          sub: user_id
        )

      hint = OpenId.sign_id_token(id_token, config)
      params = %{"id_token_hint" => hint, "user_id" => user_id}

      assert EndSessionParams.parse_request_params(params, config, @opts) ==
               {:error, %{iss: ["is invalid"]}}
    end

    test "returns an error when the issuer is missing" do
      app = Fixtures.insert(:application, scopes: "openid")
      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)

      id_token =
        :id_token
        |> Fixtures.build(aud: app.uid, sub: user_id)
        |> Map.delete(:iss)

      hint = OpenId.sign_id_token(id_token, config)
      params = %{"id_token_hint" => hint, "user_id" => user_id}

      assert EndSessionParams.parse_request_params(params, config, @opts) ==
               {:error, %{iss: ["is invalid"]}}
    end

    test "returns an error when the id_token belongs to another user" do
      app = Fixtures.insert(:application, scopes: "openid")
      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)

      id_token =
        Fixtures.build(
          :id_token,
          aud: app.uid,
          iss: config.id_token_issuer,
          sub: 8_675_309
        )

      hint = OpenId.sign_id_token(id_token, config)
      params = %{"id_token_hint" => hint, "user_id" => user_id}

      assert EndSessionParams.parse_request_params(params, config, @opts) ==
               {:error, %{sub: ["is invalid"]}}
    end

    test "returns an error when the id token does not have the sub field" do
      app = Fixtures.insert(:application, scopes: "openid")
      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)

      id_token =
        :id_token
        |> Fixtures.build(
          aud: app.uid,
          iss: config.id_token_issuer
        )
        |> Map.delete(:sub)

      hint = OpenId.sign_id_token(id_token, config)
      params = %{"id_token_hint" => hint, "user_id" => user_id}

      assert EndSessionParams.parse_request_params(params, config, @opts) ==
               {:error, %{sub: ["is invalid"]}}
    end

    test "returns an error when post_logout_redirect_uri does not match" do
      app =
        Fixtures.insert(
          :application,
          open_id_post_logout_redirect_uri: "https://test.site/callback/abc123",
          scopes: "openid"
        )

      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)

      id_token =
        Fixtures.build(
          :id_token,
          aud: app.uid,
          iss: config.id_token_issuer,
          sub: user_id
        )

      hint = OpenId.sign_id_token(id_token, config)

      params = %{
        "id_token_hint" => hint,
        "post_logout_redirect_uri" => "fail",
        "user_id" => user_id
      }

      assert EndSessionParams.parse_request_params(params, config, @opts) ==
               {:error, %{post_logout_redirect_uri: ["is invalid"]}}
    end

    test "returns an error when post_logout_redirect_uri is given but app does not have one" do
      app = Fixtures.insert(:application, scopes: "openid")
      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)

      id_token =
        Fixtures.build(
          :id_token,
          aud: app.uid,
          iss: config.id_token_issuer,
          sub: user_id
        )

      hint = OpenId.sign_id_token(id_token, config)

      params = %{
        "id_token_hint" => hint,
        "post_logout_redirect_uri" => "https:/test.com/callback",
        "user_id" => user_id
      }

      assert EndSessionParams.parse_request_params(params, config, @opts) ==
               {:error, %{post_logout_redirect_uri: ["is invalid"]}}
    end

    test "returns an error when state is not a string" do
      app = Fixtures.insert(:application, scopes: "openid")
      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)

      id_token =
        Fixtures.build(
          :id_token,
          aud: app.uid,
          iss: config.id_token_issuer,
          sub: user_id
        )

      hint = OpenId.sign_id_token(id_token, config)

      params = %{
        "id_token_hint" => hint,
        "user_id" => user_id,
        "state" => 42
      }

      assert EndSessionParams.parse_request_params(params, config, @opts) ==
               {:error, %{state: ["is invalid"]}}
    end

    test "returns an error when the application does not have openid in scopes" do
      %{uid: app_uid} = Fixtures.insert(:application, scopes: "public write")
      %{id: user_id} = Fixtures.build_with_id(:user)
      config = Fixtures.build(:config)

      id_token =
        Fixtures.build(
          :id_token,
          aud: app_uid,
          iss: config.id_token_issuer,
          sub: user_id
        )

      hint = OpenId.sign_id_token(id_token, config)
      params = %{"id_token_hint" => hint, "user_id" => user_id}

      assert EndSessionParams.parse_request_params(params, config, @opts) ==
               {:error, %{aud: ["is invalid"]}}
    end
  end
end
