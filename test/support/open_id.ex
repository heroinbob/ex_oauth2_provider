defmodule ExOauth2Provider.Test.OpenId do
  use ExUnit.CaseTemplate

  alias ExOauth2Provider.Test.Fixtures

  def get_config do
    :ex_oauth2_provider
    |> Application.get_env(ExOauth2Provider)
    |> Keyword.fetch!(:open_id)
  end

  @doc """
  Return true if the given JWS is for a valid signed JWT.
  """
  def signed_jwt?(signed_value) do
    # This is built using the existing config... so this is an RS256 key.
    private_key = Fixtures.build(:private_rs256_key)
    %{id_token_signing_key_algorithm: algorithm} = get_config()

    assert {is_valid, %JOSE.JWT{}, %JOSE.JWS{}} =
             JOSE.JWT.verify_strict(
               private_key,
               [algorithm],
               signed_value
             )

    assert is_valid
  end

  @doc """
  Return true if the given JWS is for a valid signed JWT.
  """
  def signed_jwt?(
        signed_value,
        algorithm,
        expected_fields,
        expected_key_id \\ false
      ) do
    # This is built using the existing config... so this is an RS256 key.
    private_key = Fixtures.build(:private_rs256_key)

    assert {
             is_valid,
             %JOSE.JWT{fields: fields},
             %JOSE.JWS{
               alg: {_, :RS256},
               fields: %{"typ" => "JWT"} = header
             }
           } =
             JOSE.JWT.verify_strict(
               private_key,
               [algorithm],
               signed_value
             )

    assert is_valid
    assert fields == expected_fields

    if is_binary(expected_key_id) do
      assert Map.has_key?(header, "kid")
      key_id = Map.get(header, "kid")

      key_id == expected_key_id
    else
      # Make sure it returns true if kid is NOT present.
      not Map.has_key?(header, "kid")
    end
  end
end
