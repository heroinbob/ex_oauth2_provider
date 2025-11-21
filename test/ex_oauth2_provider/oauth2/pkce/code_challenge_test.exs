defmodule ExOauth2Provider.PKCE.CodeChallengeTest do
  use ExUnit.Case, async: true

  alias ExOauth2Provider.PKCE.CodeChallenge
  alias ExOauth2Provider.Test.PKCE

  describe "valid?/2 when challenge method is plain" do
    test "returns true for a valid challenge" do
      challenge = PKCE.generate_code_challenge(%{method: :plain})

      assert String.length(challenge) == 43
      assert CodeChallenge.valid?(challenge, "plain") == true
    end

    test "returns false when there are invalid chars" do
      challenge = PKCE.generate_code_challenge(%{method: :plain})

      assert CodeChallenge.valid?(challenge <> "=", "plain") == false
    end

    test "returns false when the length is too small" do
      # 32 octets generates a 43 char string. Anything less is too short.
      challenge = PKCE.generate_code_challenge(%{method: :plain, num_bytes: 31})

      assert String.length(challenge) == 42
      assert CodeChallenge.valid?(challenge, "plain") == false
    end

    test "returns false when the length is too long" do
      # Max length is 128 but the closest to 129 we can get to is 130.
      challenge = PKCE.generate_code_challenge(%{method: :plain, num_bytes: 97})

      assert String.length(challenge) == 130
      assert CodeChallenge.valid?(challenge, "plain") == false
    end
  end

  describe "valid?/2 when challenge method is S256" do
    test "returns true for a valid challenge" do
      challenge = PKCE.generate_code_challenge(%{method: :s256})

      assert String.length(challenge) == 43
      assert CodeChallenge.valid?(challenge, "S256") == true
    end

    test "returns false when it is not Base64 URL encoded without padding" do
      challenge = PKCE.generate_code_challenge(%{method: :s256})

      assert String.length(challenge) == 43
      assert CodeChallenge.valid?(challenge, "S256") == true
    end

    test "returns false when it is a base64 url encoded value but it isn't a sh256 hash" do
      verifier = PKCE.generate_code_verifier()

      # This will cause the byte size to be invalid on the deencoded value.
      challenge =
        :sha512
        |> :crypto.hash(verifier)
        |> PKCE.encode()

      assert String.length(challenge) >= 43
      assert String.length(challenge) <= 128
      assert CodeChallenge.valid?(challenge, "S256") == false
    end
  end
end
