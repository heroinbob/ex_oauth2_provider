defmodule ExOauth2Provider.Test.OpenId do
  use ExUnit.CaseTemplate

  alias ExOauth2Provider.OpenId.OpenIdConfig

  @doc """
  Generate a new private key for signing.
  """
  def generate_private_key(sig \\ %{"alg" => "RS256"}) do
    JOSE.JWS.generate_key(sig)
  end

  @doc """
  Generate a new token and sign it. Everything is based on the
  current config unless you pass in a new one.
  """
  def generate_signed_id_token(app, user, config \\ nil) do
    config = config || OpenIdConfig.get()
    unix = DateTime.to_unix(DateTime.utc_now())

    # Same as ExOauth2Provider.Test.Fixtures but we can't use
    # fixtures here because this file is released for others
    # test convenience. Fixtures are purely for our test needs.
    %{
      aud: app.uid,
      auth_time: unix,
      exp: unix + 600,
      iat: unix,
      iss: config.id_token_issuer,
      sub: user.id
    }
    |> sign_id_token(config)
  end

  @doc """
  Return the app config.
  """
  def get_app_config(key \\ :ex_oauth2_provider) do
    key
    |> Application.get_env(ExOauth2Provider)
    |> Keyword.fetch!(:open_id)
  end

  @doc """
  Return the private key (JWK) for the configured PEM
  """
  def get_private_key(config \\ nil) do
    config = config || get_app_config()

    config
    |> Map.get(:id_token_signing_key_pem)
    |> JOSE.JWK.from_pem()
  end

  @doc """
  Return the public key (JWK) for the configured PEM
  """
  def get_public_key(config \\ nil) do
    config = config || get_app_config()

    config
    |> get_private_key()
    |> JOSE.JWK.to_public()
  end

  @doc """
  Sign the ID token. It uses the current configuration and provides
  the accurace signature that we use so this is suitable for testing.

  ## Options

  You can specify optional behavior:

  `:without` - Provide a list of things to not include. Supports
               `:kid` and the value is expected to be a list.
  """
  def sign_id_token(id_token, config \\ nil, opts \\ []) do
    # config = config || Fixtures.build(:config)
    config = config || OpenIdConfig.get()
    without_opts = Keyword.get(opts, :without, [])

    %OpenIdConfig{
      id_token_signing_key: signing_key,
      id_token_signing_key_algorithm: algorithm
    } = config

    # NOTE: "type" => "JWT" is always present in the JWS fields after
    # verification so removing it doesn't make a difference. This is
    # Just for looks.
    jws = %{"alg" => algorithm, "typ" => "JWT"}

    jws =
      if is_binary(config.id_token_signing_key_id) or :kid not in without_opts do
        Map.put(jws, "kid", config.id_token_signing_key_id)
      else
        jws
      end

    signing_key
    |> JOSE.JWT.sign(jws, id_token)
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  @doc """
  Return true if the given JWS is for a valid signed JWT.
  """
  def signed_jwt?(signed_value) do
    # This is built using the existing config... so this is an RS256 key.
    private_key = get_private_key()
    %{id_token_signing_key_algorithm: algorithm} = get_app_config()

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
    private_key = get_private_key()

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
