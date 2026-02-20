defmodule ExOauth2Provider.Token.AuthorizationCode.RequestParamsTest do
  use ExUnit.Case, async: true

  alias ExOauth2Provider.Token.AuthorizationCode.RequestParams
  alias ExOauth2Provider.Test.Fixtures
  alias ExOauth2Provider.Test.PKCE

  describe "valid?/2" do
    test "returns true for valid params and no scope" do
      context =
        Fixtures.token_request_context(
          access_grant: Fixtures.build(:access_grant, redirect_uri: "test"),
          request: %{"redirect_uri" => "test"}
        )

      assert RequestParams.valid?(context, []) == true
    end

    test "returns true for valid params with PKCE" do
      verifier = PKCE.generate_code_verifier()
      challenge = PKCE.generate_code_challenge(verifier, :s256)
      app = Fixtures.build(:application)

      context =
        Fixtures.token_request_context_with_pkce(
          access_grant:
            Fixtures.build(
              :access_grant,
              code_challenge: challenge,
              code_challenge_method: :s256,
              redirect_uri: "test",
              scopes: app.scopes
            ),
          request: %{
            "code_verifier" => verifier,
            "redirect_uri" => "test"
          }
        )

      assert RequestParams.valid?(context, pkce: :enabled) == true
    end

    test "returns false when redirect URI is invalid" do
      context =
        Fixtures.token_request_context(
          access_grant: Fixtures.build(:access_grant, redirect_uri: "test"),
          request: %{"redirect_uri" => "different-one"}
        )

      assert RequestParams.valid?(context, []) == false
    end

    test "returns false when PKCE is invalid" do
      verifier = PKCE.generate_code_verifier()

      context =
        Fixtures.token_request_context_with_pkce(
          access_grant:
            Fixtures.build(
              :access_grant,
              code_challenge: "challenge",
              code_challenge_method: "S256",
              redirect_uri: "test"
            ),
          request: %{
            "code_verifier" => verifier,
            "redirect_uri" => "test"
          }
        )

      assert RequestParams.valid?(context, pkce: :all_methods) == false
    end

    test "returns false when the context is unexpected" do
      assert RequestParams.valid?(%{}, []) == false
      assert RequestParams.valid?(%{access_grant: "grant"}, []) == false
      assert RequestParams.valid?(%{request: "request"}, []) == false
    end
  end

  describe "valid?/2 for OpenID and scopes" do
    test "returns true when enabled on the app and openid is in grant scopes" do
      app = Fixtures.build(:application, scopes: "email openid whatever")

      grant =
        Fixtures.build(
          :access_grant,
          redirect_uri: app.redirect_uri,
          scopes: "openid email whatever"
        )

      context =
        Fixtures.token_request_context(
          client: app,
          access_grant: grant,
          request: %{"redirect_uri" => app.redirect_uri}
        )

      assert RequestParams.valid?(context, []) == true
    end

    test "returns false when enabled on the app and openid is NOT in grant scopes" do
      app = Fixtures.build(:application, scopes: "openid email whatever")

      grant =
        Fixtures.build(
          :access_grant,
          redirect_uri: app.redirect_uri,
          scopes: "email whatever"
        )

      context =
        Fixtures.token_request_context(
          client: app,
          access_grant: grant,
          request: %{"redirect_uri" => app.redirect_uri}
        )

      assert RequestParams.valid?(context, []) == false
    end
  end
end
