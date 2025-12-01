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

    test "returns true when the given list has :pkce in an enabled state" do
      assert PKCE.required?(pkce: :enabled) == true
    end

    test "returns true when the app config has PKCE enabled" do
      Application.put_env(:my_app, ExOauth2Provider, pkce: :enabled)

      assert PKCE.required?(otp_app: :my_app) == true
    end

    test "returns false when not given `:pkce` and PKCE is not configured" do
      assert PKCE.required?([]) == false
    end
  end

  describe "valid?/2 when given grant request params" do
    test "returns true for a plain challenge" do
      challenge = Test.PKCE.generate_code_challenge(%{method: :plain})
      assert PKCE.valid?(%{"code_challenge" => challenge}, pkce: :enabled) == true
    end

    test "returns true for a plain challenge with method defined" do
      challenge = Test.PKCE.generate_code_challenge(%{method: :plain})

      assert PKCE.valid?(
               %{
                 "code_challenge" => challenge,
                 "code_challenge_method" => "plain"
               },
               pkce: :enabled
             ) == true
    end

    test "returns true for a S256 challenge" do
      challenge = Test.PKCE.generate_code_challenge()

      assert PKCE.valid?(
               %{
                 "code_challenge" => challenge,
                 "code_challenge_method" => "S256"
               },
               pkce: :enabled
             ) == true
    end

    test "returns false when the challenge is invalid" do
      assert PKCE.valid?(%{"code_challenge" => "fake"}, pkce: :enabled) == false
    end

    test "returns false for an unsupported method" do
      assert PKCE.valid?(
               %{
                 "code_challenge" => Test.PKCE.generate_code_challenge(),
                 "code_challenge_method" => "wtf"
               },
               pkce: :enabled
             ) == false
    end

    test "returns the correct value when the challenge is plain and pcke is set to a particular setting" do
      challenge = Test.PKCE.generate_code_challenge(%{method: :plain})

      # Ensure the valid challenge is rejected since it's not configured
      assert PKCE.valid?(
               %{
                 "code_challenge" => challenge,
                 "code_challenge_method" => "plain"
               },
               pkce: :s256_only
             ) == false

      # Now verify the valid challenge is allowed when configured
      assert PKCE.valid?(
               %{
                 "code_challenge" => challenge,
                 "code_challenge_method" => "plain"
               },
               pkce: :plain_only
             ) == true
    end

    test "returns the correct value when the challenge is S256 and pcke is set to a particular setting" do
      challenge = Test.PKCE.generate_code_challenge(%{method: :s256})

      # Ensure the valid challenge is rejected since it's not configured
      assert PKCE.valid?(
               %{
                 "code_challenge" => challenge,
                 "code_challenge_method" => "S256"
               },
               pkce: :plain_only
             ) == false

      # Now verify the valid challenge is allowed when configured
      assert PKCE.valid?(
               %{
                 "code_challenge" => challenge,
                 "code_challenge_method" => "S256"
               },
               pkce: :s256_only
             ) == true
    end
  end

  describe "valid?/2 when given token context" do
    test "returns true for a valid verifier" do
      verifier = Test.PKCE.generate_code_verifier()
      challenge = Test.PKCE.generate_code_challenge(verifier, :s256)

      assert PKCE.valid?(
               %{
                 access_grant: %OauthAccessGrant{
                   code_challenge: challenge,
                   code_challenge_method: :s256
                 },
                 request: %{"code_verifier" => verifier}
               },
               pkce: :enabled
             ) == true
    end

    test "returns false for an invalid verifier" do
      verifier = Test.PKCE.generate_code_verifier()

      assert PKCE.valid?(
               %{
                 access_grant: %OauthAccessGrant{
                   code_challenge: "something-else",
                   code_challenge_method: :s256
                 },
                 request: %{"code_verifier" => verifier}
               },
               pkce: :enabled
             ) == false
    end

    test "returns false when the given context is unexpected" do
      challenge = Test.PKCE.generate_code_challenge()

      assert PKCE.valid?(
               %{
                 access_grant: %OauthAccessGrant{
                   code_challenge: challenge,
                   code_challenge_method: "S256"
                 },
                 request: %{}
               },
               pkce: :enabled
             ) == false

      assert PKCE.valid?(%{}, pkce: :enabled) == false
    end

    test "returns the appropriate value when the chalenge is plain and only 1 method is allowed" do
      verifier = Test.PKCE.generate_code_verifier()

      # Ensure the valid challenge is rejected since it's not configured
      assert PKCE.valid?(
               %{
                 access_grant: %OauthAccessGrant{
                   code_challenge: verifier,
                   code_challenge_method: :plain
                 },
                 request: %{"code_verifier" => verifier}
               },
               pkce: :s256_only
             ) == false

      # Now verify the valid challenge is allowed when configured
      assert PKCE.valid?(
               %{
                 access_grant: %OauthAccessGrant{
                   code_challenge: verifier,
                   code_challenge_method: :plain
                 },
                 request: %{"code_verifier" => verifier}
               },
               pkce: :plain_only
             ) == true
    end

    test "returns the appropriate value when the chalenge is S256 and only 1 method is allowed" do
      verifier = Test.PKCE.generate_code_verifier()
      challenge = Test.PKCE.generate_code_challenge(verifier, :s256)

      # Ensure the valid challenge is rejected since it's not configured
      assert PKCE.valid?(
               %{
                 access_grant: %OauthAccessGrant{
                   code_challenge: challenge,
                   code_challenge_method: :s256
                 },
                 request: %{"code_verifier" => verifier}
               },
               pkce: :plain_only
             ) == false

      # Now verify the valid challenge is allowed when configured
      assert PKCE.valid?(
               %{
                 access_grant: %OauthAccessGrant{
                   code_challenge: challenge,
                   code_challenge_method: :s256
                 },
                 request: %{"code_verifier" => verifier}
               },
               pkce: :s256_only
             ) == true
    end
  end

  describe "valid?/2 when given something unexpected" do
    test "returns an error" do
      assert PKCE.valid?(%{}, pkce: :enabled) == false
    end
  end
end
