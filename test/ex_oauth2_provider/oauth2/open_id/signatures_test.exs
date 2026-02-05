defmodule ExOauth2Provider.OpenId.SignaturesTest do
  use ExOauth2Provider.TestCase, async: false

  alias ExOauth2Provider.OpenId.Signatures
  alias ExOauth2Provider.Test.Fixtures
  alias ExOauth2Provider.Test.OpenId

  describe "create!/3" do
    test "returns the given value signed using the app config" do
      %{
        id_token_signing_key_algorithm: algorithm,
        id_token_signing_key_id: expected_key_id
      } = Fixtures.build(:config)

      public_key = OpenId.get_public_key()

      result =
        Signatures.create!(
          %{test: "success!"},
          otp_app: :ex_oauth2_provider
        )

      assert {
               is_valid,
               %JOSE.JWT{fields: jwt_fields},
               %JOSE.JWS{
                 alg: {_, :RS256},
                 fields: jws_fields
               }
             } =
               JOSE.JWT.verify_strict(
                 public_key,
                 [algorithm],
                 result
               )

      assert is_valid
      assert jwt_fields == %{"test" => "success!"}

      assert jws_fields == %{
               "kid" => expected_key_id,
               "typ" => "JWT"
             }
    end

    test "does not include the key ID when it is not configured" do
      %{id_token_signing_key_algorithm: algorithm} =
        config = OpenId.get_app_config() |> Map.delete(:id_token_signing_key_id)

      public_key = OpenId.get_public_key()

      result =
        Signatures.create!(
          %{test: "success!"},
          otp_app: :ex_oauth2_provider,
          open_id: config
        )

      assert {
               is_valid,
               _jwt,
               %JOSE.JWS{fields: jws_fields}
             } =
               JOSE.JWT.verify_strict(
                 public_key,
                 [algorithm],
                 result
               )

      assert is_valid
      assert jws_fields == %{"typ" => "JWT"}
    end
  end

  describe "verify" do
    test "returns the id token when it is valid" do
      token = Fixtures.build(:id_token)
      config = Fixtures.build(:config)
      signed = OpenId.sign_id_token(token, config)

      assert Signatures.verify(signed, config) == {:ok, token}
    end

    test "returns :error when the signature is not authentic" do
      token = Fixtures.build(:id_token)
      config = Fixtures.build(:config)
      # Sign the token with a differet key.
      custom_key = OpenId.generate_private_key()
      signed = OpenId.sign_id_token(token, %{config | id_token_signing_key: custom_key})

      assert Signatures.verify(signed, config) == {:error, :wrong_signature}
    end

    test "returns :error when the signature kid does not match" do
      token = Fixtures.build(:id_token)
      config = Fixtures.build(:config)
      signed = OpenId.sign_id_token(token, %{config | id_token_signing_key_id: "foo"})

      assert Signatures.verify(signed, config) == {:error, :invalid_key_id}
    end

    test "returns :error when the value is not signed" do
      config = Fixtures.build(:config)

      assert Signatures.verify("not-a-signed-value", config) == {:error, :unsupported_value}
      assert Signatures.verify(nil, config) == {:error, :unsupported_value}
    end
  end
end
