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
      assert PKCE.valid?(%{"code_challenge" => challenge}) == true
    end

    test "returns true for a plain challenge with method defined" do
      challenge = Test.PKCE.generate_code_challenge(%{method: :plain})

      assert PKCE.valid?(%{
               "code_challenge" => challenge,
               "code_challenge_method" => "plain"
             }) == true
    end

    test "returns true for a S256 challenge" do
      challenge = Test.PKCE.generate_code_challenge()

      assert PKCE.valid?(%{
               "code_challenge" => challenge,
               "code_challenge_method" => "S256"
             }) == true
    end

    test "returns false when the challenge is invalid" do
      assert PKCE.valid?(%{"code_challenge" => "fake"}) == false
    end

    test "returns false for an unsupported method" do
      assert PKCE.valid?(%{
               "code_challenge" => Test.PKCE.generate_code_challenge(),
               "code_challenge_method" => "wtf"
             }) == false
    end
  end

  describe "valid?/1 when given grant request params and the allow option" do
    test "returns false when the method is not allowed" do
      lookup = %{plain: "plain", s256: "S256"}

      for method <- [:plain, :s256] do
        challenge = Test.PKCE.generate_code_challenge(%{method: method})
        other_method = if method == :plain, do: :s256, else: :plain

        # Ensure the valid challenge is rejected since it's not configured
        assert PKCE.valid?(
                 %{
                   "code_challenge" => challenge,
                   "code_challenge_method" => lookup[method]
                 },
                 allow: other_method
               ) == false

        # Now verify the valid challenge is allowed when configured
        assert PKCE.valid?(
                 %{
                   "code_challenge" => challenge,
                   "code_challenge_method" => lookup[method]
                 },
                 allow: method
               ) == true
      end
    end

    # It should accept a list too.
    assert PKCE.valid?(
             %{
               "code_challenge" => Test.PKCE.generate_code_challenge(),
               "code_challenge_method" => "S256"
             },
             allow: [:plain, :s256]
           ) == true
  end

  describe "valid?/1 when given token context" do
    test "returns true for a valid verifier" do
      verifier = Test.PKCE.generate_code_verifier()
      challenge = Test.PKCE.generate_code_challenge(verifier, :s256)

      assert PKCE.valid?(%{
               access_grant: %OauthAccessGrant{
                 code_challenge: challenge,
                 code_challenge_method: :s256
               },
               request: %{"code_verifier" => verifier}
             }) == true
    end

    test "returns false for an invalid verifier" do
      verifier = Test.PKCE.generate_code_verifier()

      assert PKCE.valid?(%{
               access_grant: %OauthAccessGrant{
                 code_challenge: "something-else",
                 code_challenge_method: :s256
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

  describe "valid?/1 when given token context and the allow option" do
    test "returns false for methods that are not allowed" do
      verifier = Test.PKCE.generate_code_verifier()

      for method <- [:plain, :s256] do
        challenge = Test.PKCE.generate_code_challenge(verifier, method)
        other_method = if method == :plain, do: :s256, else: :plain

        # Ensure the valid challenge is rejected since it's not configured
        result =
          PKCE.valid?(
            %{
              access_grant: %OauthAccessGrant{
                code_challenge: challenge,
                code_challenge_method: method
              },
              request: %{"code_verifier" => verifier}
            },
            allow: other_method
          )

        assert result == false,
               "expected to receive false, received #{inspect(result)} for method #{inspect(method)} allowing other method #{inspect(other_method)}"

        # Now verify the valid challenge is allowed when configured
        result =
          PKCE.valid?(
            %{
              access_grant: %OauthAccessGrant{
                code_challenge: challenge,
                code_challenge_method: method
              },
              request: %{"code_verifier" => verifier}
            },
            allow: method
          )

        assert result == true,
               "expected to receive true, received #{inspect(result)} for method #{inspect(method)}"
      end

      # It should accept a list too.
      assert PKCE.valid?(
               %{
                 access_grant: %OauthAccessGrant{
                   code_challenge: Test.PKCE.generate_code_challenge(verifier, :s256),
                   code_challenge_method: :s256
                 },
                 request: %{"code_verifier" => verifier}
               },
               allow: [:plain, :s256]
             ) == true
    end
  end

  describe "valid?/1 when given something unexpected" do
    test "returns an error" do
      assert PKCE.valid?(%{}) == false
    end
  end
end
