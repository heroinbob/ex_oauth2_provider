defmodule ExOauth2Provider.AuthorizationTest do
  use ExOauth2Provider.TestCase

  alias Dummy.OauthApplications.OauthApplication
  alias ExOauth2Provider.Authorization
  alias ExOauth2Provider.DeviceGrants
  alias ExOauth2Provider.Test.{Fixtures, PKCE, QueryHelpers}

  @client_id "Jf5rM8hQBc"
  @client_secret "secret"

  @valid_request %{
    "client_id" => @client_id,
    "response_type" => "code",
    "scope" => "public read write"
  }

  @access_denied %{
    error: :access_denied,
    error_description: "The resource owner or authorization server denied the request."
  }

  @invalid_request %{
    error: :invalid_request,
    error_description:
      "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
  }

  @invalid_response_type %{
    error: :unsupported_response_type,
    error_description: "The authorization server does not support this response type."
  }
  @config [otp_app: :ex_oauth2_provider]

  setup do
    user = Fixtures.resource_owner()

    application =
      Fixtures.application(resource_owner: user, uid: @client_id, secret: @client_secret)

    {:ok, %{resource_owner: user, application: application}}
  end

  describe "preauthorize_device/2" do
    test "forces the request to be device_code and returns an :ok tuple with the device and user code",
         %{application: application} do
      response =
        %{"client_id" => application.uid}
        |> Authorization.preauthorize_device(@config)

      assert {
               :ok,
               %{
                 device_code: _device_code,
                 user_code: _user_code
               }
             } = response
    end
  end

  describe "preauthorize/3" do
    test "returns the application and scopes when the request is valid", %{
      application: %{id: app_id},
      resource_owner: owner
    } do
      assert {:ok, %OauthApplication{id: ^app_id}, ~w[public read write]} =
               Authorization.preauthorize(
                 owner,
                 @valid_request,
                 @config
               )
    end

    test "returns error when missing response_type", %{resource_owner: resource_owner} do
      params = Map.delete(@valid_request, "response_type")

      assert Authorization.preauthorize(resource_owner, params, @config) ==
               {:error, @invalid_request, :bad_request}
    end

    test "redirects when missing response_type", %{
      resource_owner: resource_owner,
      application: application
    } do
      QueryHelpers.change!(application,
        redirect_uri: "#{application.redirect_uri}\nhttps://example.com/path"
      )

      params =
        @valid_request
        |> Map.delete("response_type")
        |> Map.merge(%{"redirect_uri" => "https://example.com/path?param=1", "state" => 40_612})

      assert Authorization.preauthorize(resource_owner, params, @config) ==
               {:redirect,
                "https://example.com/path?error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+unsupported+parameter+value%2C+or+is+otherwise+malformed.&param=1&state=40612"}
    end

    test "returns error when unsupported response type", %{resource_owner: resource_owner} do
      params = Map.merge(@valid_request, %{"response_type" => "invalid"})

      assert Authorization.preauthorize(resource_owner, params, @config) ==
               {:error, @invalid_response_type, :unprocessable_entity}
    end

    test "redirects when unsupported response_type", %{
      resource_owner: resource_owner,
      application: application
    } do
      QueryHelpers.change!(application,
        redirect_uri: "#{application.redirect_uri}\nhttps://example.com/path"
      )

      params =
        @valid_request
        |> Map.merge(%{"response_type" => "invalid"})
        |> Map.merge(%{"redirect_uri" => "https://example.com/path?param=1", "state" => 40_612})

      assert Authorization.preauthorize(resource_owner, params, @config) ==
               {:redirect,
                "https://example.com/path?error=unsupported_response_type&error_description=The+authorization+server+does+not+support+this+response+type.&param=1&state=40612"}
    end

    test "supports PKCE", %{application: %{id: app_id}, resource_owner: owner} do
      code_challenge = PKCE.generate_code_challenge()
      config = [{:pkce, :all_methods} | @config]

      request =
        Map.merge(
          @valid_request,
          %{
            "code_challenge" => code_challenge,
            "code_challenge_method" => "S256"
          }
        )

      assert {:ok, %OauthApplication{id: ^app_id}, ~w[public read write]} =
               Authorization.preauthorize(owner, request, config)

      request =
        Map.merge(
          @valid_request,
          %{
            "code_challenge" => code_challenge,
            "code_challenge_method" => "EXPLODE!!!"
          }
        )

      assert {:error, %{error: :invalid_request}, _bad_request} =
               Authorization.preauthorize(owner, request, config)
    end
  end

  describe "authorize/3" do
    test "returns error when missing response_type", %{resource_owner: resource_owner} do
      params = Map.delete(@valid_request, "response_type")

      assert Authorization.authorize(resource_owner, params, @config) ==
               {:error, @invalid_request, :bad_request}
    end

    test "rejects when unsupported response type", %{resource_owner: resource_owner} do
      params = Map.merge(@valid_request, %{"response_type" => "invalid"})

      assert Authorization.authorize(resource_owner, params, @config) ==
               {:error, @invalid_response_type, :unprocessable_entity}
    end

    test "returns the response of the Authorization.Code strategy", %{resource_owner: owner} do
      {:native_redirect, %{code: _code}} =
        Authorization.authorize(
          owner,
          @valid_request,
          @config
        )
    end

    test "supports the PKCE option", %{resource_owner: owner} do
      code_challenge = PKCE.generate_code_challenge()
      config = [{:pkce, :all_methods} | @config]

      request =
        Map.merge(
          @valid_request,
          %{
            "code_challenge" => code_challenge,
            "code_challenge_method" => "S256"
          }
        )

      {:native_redirect, %{code: _code}} = Authorization.authorize(owner, request, config)

      request =
        Map.merge(
          @valid_request,
          %{
            "code_challenge" => code_challenge,
            "code_challenge_method" => "FIRE!!!"
          }
        )

      {:error, %{error: :invalid_request}, _bad_request} =
        Authorization.authorize(owner, request, config)
    end
  end

  describe "authorize_device/3" do
    test "returns an :ok tuple with the user code", context do
      %{application: application, resource_owner: resource_owner} = context
      grant = Fixtures.device_grant(application: application)

      response =
        resource_owner
        |> Authorization.authorize_device(%{"user_code" => grant.user_code}, @config)

      assert {:ok, authorized_grant} = response
      assert grant.id == authorized_grant.id
      assert DeviceGrants.authorized?(authorized_grant)
    end
  end

  describe "deny/3" do
    test "blocks the request when the request is valid", %{resource_owner: resource_owner} do
      assert Authorization.deny(resource_owner, @valid_request, @config) ==
               {:error, @access_denied, :unauthorized}
    end

    test "returns error when missing response_type", %{resource_owner: resource_owner} do
      params = Map.delete(@valid_request, "response_type")

      assert Authorization.deny(resource_owner, params, @config) ==
               {:error, @invalid_request, :bad_request}
    end

    test "rejects when unsupported response type", %{resource_owner: resource_owner} do
      params = Map.merge(@valid_request, %{"response_type" => "invalid"})

      assert Authorization.deny(resource_owner, params, @config) ==
               {:error, @invalid_response_type, :unprocessable_entity}
    end

    test "supports PKCE", %{resource_owner: resource_owner} do
      code_challenge = PKCE.generate_code_challenge()
      config = [{:pkce, :all_methods} | @config]

      request =
        Map.merge(
          @valid_request,
          %{
            "code_challenge" => code_challenge,
            "code_challenge_method" => "S256"
          }
        )

      assert Authorization.deny(resource_owner, request, config) ==
               {:error, @access_denied, :unauthorized}

      request =
        Map.merge(
          @valid_request,
          %{
            "code_challenge" => code_challenge,
            "code_challenge_method" => "WRONG!!!"
          }
        )

      assert Authorization.deny(resource_owner, request, config) ==
               {:error, @invalid_request, :bad_request}
    end
  end
end
