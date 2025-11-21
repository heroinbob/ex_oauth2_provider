defmodule ExOauth2Provider.Authorization.PKCE.CodeVerifierTest do
  use ExUnit.Case, async: true

  alias ExOauth2Provider.Authorization.PKCE.CodeVerifier
  alias ExOauth2Provider.Test.PKCE

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
