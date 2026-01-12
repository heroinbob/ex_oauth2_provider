defmodule ExOauth2Provider.Authorization.Code.RequestParamsTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Authorization.Code.RequestParams
  alias ExOauth2Provider.Config
  alias ExOauth2Provider.Test.Fixtures
  alias ExOauth2Provider.Test.PKCE

  describe "to_access_grant_params/2" do
    test "returns a map of params for creating an access grant" do
      expires_in = Config.authorization_code_expires_in(otp_app: :ex_oauth2_provider)

      context =
        Fixtures.authorization_request_context(
          request: %{
            "redirect_uri" => "test",
            "scope" => "foo"
          }
        )

      assert %{
               expires_in: ^expires_in,
               redirect_uri: "test",
               scopes: "foo"
             } =
               grant_params =
               RequestParams.to_access_grant_params(context, otp_app: :ex_oauth2_provider)

      refute Map.has_key?(grant_params, :code_challenge)
      refute Map.has_key?(grant_params, :code_challenge_method)
    end

    test "does not include redirect_uri when it's missing" do
      context =
        Fixtures.authorization_request_context(
          request: %{
            # "redirect_uri" => "test",
            "scope" => "foo"
          }
        )

      assert %{expires_in: _} =
               grant_params =
               RequestParams.to_access_grant_params(context, otp_app: :ex_oauth2_provider)

      refute Map.has_key?(grant_params, :redirect_uri)
    end

    test "does not include scopes when it's missing" do
      context =
        Fixtures.authorization_request_context(
          request: %{
            "redirect_uri" => "test"
          }
        )

      assert %{expires_in: _} =
               grant_params =
               RequestParams.to_access_grant_params(context, otp_app: :ex_oauth2_provider)

      refute Map.has_key?(grant_params, :scopes)
    end

    test "includes PKCE fields when PKCE is enabled" do
      %{request: %{"code_challenge" => challenge}} =
        context = Fixtures.authorization_request_context_with_pkce()

      assert %{
               code_challenge: ^challenge,
               code_challenge_method: "S256"
             } = RequestParams.to_access_grant_params(context, pkce: :all_methods)
    end
  end

  describe "validate/2" do
    test "returns :ok when the authorization context is valid" do
      owner = Fixtures.insert(:user)
      application = Fixtures.insert(:application, owner: owner)

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => application.redirect_uri,
            "scope" => application.scopes
          },
          resource_owner: owner
        )

      assert RequestParams.validate(context, otp_app: :ex_oauth2_provider) == :ok
    end

    test "returns :ok when the authorization context is valid with PKCE enabled" do
      owner = Fixtures.insert(:user)
      application = Fixtures.insert(:application, owner: owner)

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "code_challenge" => PKCE.generate_code_challenge(),
            "code_challenge_method" => "S256",
            "redirect_uri" => application.redirect_uri,
            "scope" => application.scopes
          },
          resource_owner: owner
        )

      assert RequestParams.validate(context, pkce: :all_methods) == :ok
    end

    test "returns :invalid_request when the resource_owner is invalid" do
      application = Fixtures.insert(:application)

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => application.redirect_uri,
            "scope" => application.scopes
          },
          # Owner must be a struct to be considered valid.
          resource_owner: %{id: "abc"}
        )

      assert RequestParams.validate(context, otp_app: :ex_oauth2_provider) ==
               {:error, :invalid_resource_owner}
    end

    test "returns :invalid_redirect_uri when the redirect_uri is invalid" do
      owner = Fixtures.insert(:user)
      application = Fixtures.insert(:application, owner: owner)

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => "abc",
            "scope" => application.scopes
          },
          resource_owner: owner
        )

      assert RequestParams.validate(context, otp_app: :ex_oauth2_provider) ==
               {:error, :invalid_redirect_uri}
    end

    test "returns :invalid_scopes when the scope is invalid" do
      owner = Fixtures.insert(:user)
      application = Fixtures.insert(:application, owner: owner)

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => application.redirect_uri,
            # Include one not in the application scopes!
            "scope" => application.scopes <> " abc"
          },
          resource_owner: owner
        )

      assert RequestParams.validate(context, otp_app: :ex_oauth2_provider) ==
               {:error, :invalid_scopes}
    end

    test "returns :invalid_pkce when the PKCE info is invalid" do
      owner = Fixtures.insert(:user)
      application = Fixtures.insert(:application, owner: owner)

      context =
        Fixtures.authorization_request_context_with_pkce(
          client: application,
          request: %{
            "code_challenge" => "abc",
            "code_challenge_method" => "S256",
            "redirect_uri" => application.redirect_uri,
            "scope" => application.scopes
          },
          resource_owner: owner
        )

      assert RequestParams.validate(context, pkce: :all_methods) == {:error, :invalid_pkce}
    end

    test "supports non-native redirect URI" do
      owner = Fixtures.insert(:user)

      application =
        Fixtures.insert(
          :application,
          redirect_uri: "https://my-site.com/authorize",
          owner: owner
        )

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => application.redirect_uri,
            "scope" => application.scopes
          },
          resource_owner: owner
        )

      assert RequestParams.validate(context, otp_app: :ex_oauth2_provider) == :ok
    end

    test "ignores PKCE fields when not enabled" do
      owner = Fixtures.insert(:user)
      application = Fixtures.insert(:application, owner: owner)

      # Gave it a bad challenge so it'd fail when PKCE is enabled.
      context =
        Fixtures.authorization_request_context_with_pkce(
          client: application,
          request: %{
            "code_challenge" => "abc",
            "code_challenge_method" => "S256",
            "redirect_uri" => application.redirect_uri,
            "scope" => application.scopes
          },
          resource_owner: owner
        )

      assert RequestParams.validate(context, otp_app: :ex_oauth2_provider) == :ok
    end

    test "returns an error when there is a problem with OpenID" do
      owner = Fixtures.build(:user)

      application =
        Fixtures.insert(
          :application,
          open_id_settings: Fixtures.build(:open_id_settings, enforcement_policy: :always),
          owner: owner,
          scopes: "public openid read write"
        )

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => application.redirect_uri,
            "scope" => "read write"
          },
          resource_owner: owner
        )

      assert RequestParams.validate(context, otp_app: :ex_oauth2_provider) ==
               {:error, :invalid_open_id}
    end

    test "returns :ok when OpenID is enabled and provided" do
      owner = Fixtures.build(:user)

      application =
        Fixtures.insert(
          :application,
          open_id_settings: Fixtures.build(:open_id_settings, enforcement_policy: :always),
          owner: owner,
          scopes: "public openid read write"
        )

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => application.redirect_uri,
            "scope" => "read write openid"
          },
          resource_owner: owner
        )

      assert RequestParams.validate(context, otp_app: :ex_oauth2_provider) == :ok
    end
  end
end
