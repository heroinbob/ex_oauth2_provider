defmodule ExOauth2Provider.PKCE.CodeVerifierTest do
  use ExUnit.Case, async: true

  alias ExOauth2Provider.PKCE.CodeVerifier
  alias ExOauth2Provider.Test.PKCE

  describe "valid_format?/1" do
    test "returns true when the string meets RFC specs" do
      verifier = PKCE.generate_code_verifier()

      assert CodeVerifier.valid_format?(verifier) == true
    end

    test "returns false when the string does not meet RFC specs" do
      # make it too short
      verifier = PKCE.generate_code_verifier(%{num_bytes: 31})
      assert String.length(verifier) == 42
      assert CodeVerifier.valid_format?(verifier) == false

      # make it too long
      verifier = PKCE.generate_code_verifier(%{num_bytes: 97})
      assert String.length(verifier) == 130
      assert CodeVerifier.valid_format?(verifier) == false

      # invalid chars
      verifier = PKCE.generate_code_verifier() <> "="
      assert CodeVerifier.valid_format?(verifier) == false
    end

    test "returns false when the value is not a string" do
      assert CodeVerifier.valid_format?(nil) == false
      assert CodeVerifier.valid_format?(123) == false
      assert CodeVerifier.valid_format?(<<8, 6, 7, 5, 3, 0, 9>>) == false
    end
  end

  describe "valid?/2 when challenge method is plain" do
    test "returns true for a valid verifier" do
      verifier = PKCE.generate_code_verifier()

      assert CodeVerifier.valid?(verifier, verifier, "plain") == true
    end

    test "returns false when they aren't identical" do
      verifier = PKCE.generate_code_verifier()

      assert CodeVerifier.valid?(verifier, "abc", "plain") == false
    end
  end

  describe "valid?/2 when challenge method is S256" do
    test "returns true for a valid verifier" do
      verifier = PKCE.generate_code_verifier()
      challenge = PKCE.generate_code_challenge(verifier, :s256)

      assert CodeVerifier.valid?(verifier, challenge, "S256") == true
    end

    test "returns false for an invalid verifier" do
      verifier = PKCE.generate_code_verifier()

      # This challenge is based on another verifier.
      challenge = PKCE.generate_code_challenge(%{method: :s256})

      assert CodeVerifier.valid?(verifier, challenge, "S256") == false
    end
  end
end
