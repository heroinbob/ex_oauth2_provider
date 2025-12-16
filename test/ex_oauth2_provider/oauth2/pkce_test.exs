defmodule ExOauth2Provider.PKCETest do
  use ExUnit.Case, async: true

  alias Dummy.OauthApplications.OauthApplication
  alias ExOauth2Provider.PKCE
  alias ExOauth2Provider.Test

  describe "required?/2" do
    setup do
      config = Application.get_env(:ex_oauth2_provider, ExOauth2Provider)

      on_exit(fn ->
        Application.put_env(:ex_oauth2_provider, ExOauth2Provider, config)
      end)
    end

    test "returns true when the app setting is in an enabled state" do
      context =
        Test.Fixtures.authorization_request_context(client: %OauthApplication{pkce: :all_methods})

      assert PKCE.required?(context, pkce: :disabled) == true
    end

    test "returns true when the app setting is :disabled but the given config has :pkce in an enabled state" do
      context =
        Test.Fixtures.authorization_request_context(client: %OauthApplication{pkce: :disabled})

      assert PKCE.required?(context, pkce: :all_methods) == true
    end

    test "returns true when the app setting is :disabled but the otp app config has PKCE enabled" do
      Application.put_env(:my_app, ExOauth2Provider, pkce: :all_methods)

      context =
        Test.Fixtures.authorization_request_context(client: %OauthApplication{pkce: :disabled})

      assert PKCE.required?(context, otp_app: :my_app) == true
    end

    test "returns false when app is disabled and there is no config value" do
      context =
        Test.Fixtures.authorization_request_context(client: %OauthApplication{pkce: :disabled})

      assert PKCE.required?(context, []) == false
    end

    test "returns false when everything is disabled explicitly" do
      context =
        Test.Fixtures.authorization_request_context(client: %OauthApplication{pkce: :disabled})

      assert PKCE.required?(context, pkce: :disabled) == false
    end

    test "supports being given a client instead of a context with a client" do
      assert PKCE.required?(%OauthApplication{pkce: :all_methods}, pkce: :disabled) == true
      assert PKCE.required?(%OauthApplication{pkce: :disabled}, pkce: :disabled) == false
    end
  end

  describe "valid?/2 when given grant request params" do
    test "returns true for a plain challenge" do
      context =
        Test.Fixtures.authorization_request_context_with_pkce(code_challenge_method: :plain)

      assert PKCE.valid?(context, pkce: :all_methods) == true
    end

    test "returns true for a plain challenge with only code_challenge defined" do
      %{request: request} =
        context =
        Test.Fixtures.authorization_request_context_with_pkce(code_challenge_method: :plain)

      context = %{context | request: Map.delete(request, "code_challenge_method")}

      assert PKCE.valid?(context, pkce: :all_methods) == true
    end

    test "returns true for a S256 challenge" do
      context =
        Test.Fixtures.authorization_request_context_with_pkce(code_challenge_method: :s256)

      assert PKCE.valid?(context, pkce: :all_methods) == true
    end

    test "returns false when the challenge is invalid" do
      context =
        Test.Fixtures.authorization_request_context_with_pkce(code_challenge: "fake")

      assert PKCE.valid?(context, pkce: :all_methods) == false
    end

    test "returns false for an unsupported method" do
      context =
        Test.Fixtures.authorization_request_context_with_pkce(
          code_challenge_method_request_param: "wtf"
        )

      assert PKCE.valid?(context, pkce: :all_methods) == false
    end

    test "returns the correct value when the challenge is plain and pcke is set to a particular setting" do
      # Set app setting to disabled so we can defer to the config and pass that in for quick tests.
      context =
        Test.Fixtures.authorization_request_context_with_pkce(
          app_setting: :disabled,
          code_challenge_method: :plain
        )

      # Ensure the valid challenge is rejected since it's not configured
      assert PKCE.valid?(context, pkce: :s256_only) == false

      # Now verify the valid challenge is allowed when configured
      assert PKCE.valid?(context, pkce: :plain_only) == true
    end

    test "returns the correct value when the challenge is S256 and pcke is set to a particular setting" do
      # Set app setting to disabled so we can defer to the config and pass that in for quick tests.
      context =
        Test.Fixtures.authorization_request_context_with_pkce(app_setting: :disabled)

      # Ensure the valid challenge is rejected since it's not configured
      assert PKCE.valid?(context, pkce: :plain_only) == false

      # Now verify the valid challenge is allowed when configured
      assert PKCE.valid?(context, pkce: :s256_only) == true
    end

    test "returns true when the client setting is enabled and takes priority over config" do
      context =
        Test.Fixtures.authorization_request_context_with_pkce(
          app_setting: :s256_only,
          code_challenge_method: :s256
        )

      assert PKCE.valid?(context, pkce: :disabled) == true

      context =
        Test.Fixtures.authorization_request_context_with_pkce(
          app_setting: :plain_only,
          code_challenge_method: :plain
        )

      assert PKCE.valid?(context, pkce: :disabled) == true

      # Both must be accepted for :all_methods
      for method <- [:s256, :plain] do
        context =
          Test.Fixtures.authorization_request_context_with_pkce(
            app_setting: :all_methods,
            code_challenge_method: method
          )

        assert PKCE.valid?(context, pkce: :disabled) == true
      end
    end
  end

  describe "valid?/2 when given token context" do
    test "returns true for a valid verifier" do
      context = Test.Fixtures.token_request_context_with_pkce()

      assert PKCE.valid?(context, []) == true
    end

    test "returns false for an invalid verifier" do
      context = Test.Fixtures.token_request_context_with_pkce(code_challenge: "something-invalid")

      assert PKCE.valid?(context, []) == false
    end

    test "returns false when the given context is unexpected" do
      context = Test.Fixtures.token_request_context_with_pkce(request: %{"foo" => "baz"})

      assert PKCE.valid?(context, []) == false
      assert PKCE.valid?(%{}, pkce: :all_methods) == false
    end

    test "returns the appropriate value when the challenge is plain and only 1 method is allowed" do
      # Ensure the valid challenge is rejected since it's not configured.
      # Here the app is disabled so it defers to the config.
      context =
        Test.Fixtures.token_request_context_with_pkce(
          app_setting: :s256_only,
          code_challenge_method: :plain
        )

      assert PKCE.valid?(context, []) == false

      # Now verify the valid challenge is allowed when configured
      context =
        Test.Fixtures.token_request_context_with_pkce(
          app_setting: :plain_only,
          code_challenge_method: :plain
        )

      assert PKCE.valid?(context, []) == true
    end

    test "returns the appropriate value when the chalenge is S256 and only 1 method is allowed" do
      # Ensure the valid challenge is rejected since it's not configured
      context =
        Test.Fixtures.token_request_context_with_pkce(
          app_setting: :plain_only,
          code_challenge_method: :s256
        )

      assert PKCE.valid?(context, []) == false

      # Now verify the valid challenge is allowed when configured
      context =
        Test.Fixtures.token_request_context_with_pkce(
          app_setting: :s256_only,
          code_challenge_method: :s256
        )

      assert PKCE.valid?(context, []) == true
    end

    test "defers to the config when the application setting is :disabled" do
      context =
        Test.Fixtures.token_request_context_with_pkce(
          app_setting: :disabled,
          code_challenge_method: :s256
        )

      # NOTE: :disabled is not tested because one should not call valid?/2
      # when PKCE is not required. It's required when the app or config
      # have a setting so when both are disabled we want it to crash because
      # you shouldn't try to determine if it's valid when it's disabled.
      assert PKCE.valid?(context, pkce: :all_methods) == true
      assert PKCE.valid?(context, pkce: :s256_only) == true
      assert PKCE.valid?(context, pkce: :plain_only) == false

      context =
        Test.Fixtures.token_request_context_with_pkce(
          app_setting: :disabled,
          code_challenge_method: :plain
        )

      assert PKCE.valid?(context, pkce: :all_methods) == true
      assert PKCE.valid?(context, pkce: :plain_only) == true
      assert PKCE.valid?(context, pkce: :s256_only) == false
    end
  end

  describe "valid?/2 when given something unexpected" do
    test "returns an error" do
      assert PKCE.valid?(%{}, pkce: :all_methods) == false
    end
  end
end
