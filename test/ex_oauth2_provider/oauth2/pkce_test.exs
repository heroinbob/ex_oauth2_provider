defmodule ExOauth2Provider.PKCETest do
  use ExUnit.Case, async: true

  alias Dummy.OauthAccessGrants.OauthAccessGrant
  alias ExOauth2Provider.PKCE
  alias ExOauth2Provider.Test

  describe "required?/1" do
    setup do
      config = Application.get_env(:ex_oauth2_provider, ExOauth2Provider)

      on_exit(fn ->
        Application.put_env(:ex_oauth2_provider, ExOauth2Provider, config)
      end)
    end

    test "returns true when the given list has `with: :pkce`" do
      assert PKCE.required?(with: :pkce) == true
    end

    test "returns true when the given list has `with` as a list with `:pkce`" do
      assert PKCE.required?(with: [:foo, :baz, :pkce]) == true
    end

    test "returns true when the app config has PKCE enabled" do
      Application.put_env(:my_app, ExOauth2Provider, use_pkce: true)

      assert PKCE.required?(otp_app: :my_app) == true
    end

    test "returns false when `:with` is not `:pkce`" do
      assert PKCE.required?(with: :test) == false
    end

    test "returns true when the given list has `with` as a list without `:pkce`" do
      assert PKCE.required?(with: [:foo, :baz]) == false
    end

    test "returns false when not given `:with` and PKCE is not configured" do
      assert PKCE.required?([]) == false
    end
  end

  describe "valid?/1 when given grant request params" do
    test "returns true for a plain challenge" do
      challenge = Test.PKCE.generate_code_challenge(%{method: :plain})
      assert PKCE.valid?(%{"code_challenge" => challenge})
    end

    test "returns true for a plain challenge with method defined" do
      challenge = Test.PKCE.generate_code_challenge(%{method: :plain})
      assert PKCE.valid?(%{"code_challenge" => challenge, "code_challenge_method" => "plain"})
    end

    test "returns true for a S256 challenge" do
      challenge = Test.PKCE.generate_code_challenge()
      assert PKCE.valid?(%{"code_challenge" => challenge, "code_challenge_method" => "S256"})
    end

    test "returns false when the challenge is invalid" do
      assert PKCE.valid?(%{"code_challenge" => "fake"}) == false
    end
  end

  describe "valid?/1 when given token context" do
    test "returns true for a valid verifier" do
      verifier = Test.PKCE.generate_code_verifier()
      challenge = Test.PKCE.generate_code_challenge(verifier, :s256)

      assert PKCE.valid?(%{
               access_grant: %OauthAccessGrant{
                 code_challenge: challenge,
                 code_challenge_method: "S256"
               },
               request: %{"code_verifier" => verifier}
             }) == true
    end

    test "returns false for an invalid verifier" do
      verifier = Test.PKCE.generate_code_verifier()

      assert PKCE.valid?(%{
               access_grant: %OauthAccessGrant{
                 code_challenge: "something-else",
                 code_challenge_method: "S256"
               },
               request: %{"code_verifier" => verifier}
             }) == false
    end

    test "returns false when the given context is unexpected" do
      challenge = Test.PKCE.generate_code_challenge()

      assert PKCE.valid?(%{
               access_grant: %OauthAccessGrant{
                 code_challenge: challenge,
                 code_challenge_method: "S256"
               },
               request: %{}
             }) == false

      assert PKCE.valid?(%{}) == false
    end
  end

  describe "valid?/1 when given something unexpected" do
    test "returns an error" do
      assert PKCE.valid?(%{}) == false
    end
  end
end
