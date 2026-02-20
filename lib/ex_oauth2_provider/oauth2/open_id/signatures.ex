defmodule ExOauth2Provider.OpenId.Signatures do
  alias ExOauth2Provider.OpenId.Errors.SigningError
  alias ExOauth2Provider.OpenId.IdToken
  alias ExOauth2Provider.OpenId.OpenIdConfig

  @algorithm_lookup %{
    "RS256" => :RS256
  }

  @spec create!(value :: map(), opts :: keyword()) :: String.t()
  def create!(value, opts) when is_list(opts) do
    %{
      id_token_signing_key: signing_key,
      id_token_signing_key_algorithm: algorithm,
      id_token_signing_key_id: key_id
    } = OpenIdConfig.get(opts)

    header = build_signing_header(algorithm, key_id)

    {_, compact_jws} =
      signing_key
      |> JOSE.JWT.sign(header, value)
      |> JOSE.JWS.compact()

    compact_jws
  rescue
    error -> raise SigningError.new(error)
  end

  defp build_signing_header(algorithm, key_id) do
    # The type is present when you verify regardless of
    # if you set it here. This just acts as documentation
    # as we expect typ to always be JWT
    header = %{"alg" => algorithm, "typ" => "JWT"}

    if is_binary(key_id) do
      Map.put(header, "kid", key_id)
    else
      header
    end
  end

  def verify(value, %OpenIdConfig{} = config) do
    %OpenIdConfig{
      id_token_signing_key_algorithm: algo,
      id_token_signing_key_id: key_id
    } = config

    public_key = ExOauth2Provider.OpenId.get_public_key(config)
    expected_algorithm = Map.fetch!(@algorithm_lookup, algo)

    case JOSE.JWT.verify_strict(public_key, [algo], value) do
      {false, _, _} ->
        {:error, :wrong_signature}

      {
        true,
        %JOSE.JWT{} = jwt,
        %JOSE.JWS{
          alg: {_, ^expected_algorithm},
          fields: %{"typ" => "JWT"} = fields
        }
      } ->
        if valid_key_id?(key_id, fields["kid"]) do
          {:ok, IdToken.new(jwt)}
        else
          {:error, :invalid_key_id}
        end

      {true, _, _} ->
        {:error, :invalid_jws}

      _error ->
        # It should be noted that if you pass an unsigned string to
        # verify_strict then it returns {:error, {:badarg, [<VALUE>]}}
        # where value is what you passed in. That's not described in
        # the typespec or documentation so this is designed to be a
        # catchall for _anything_ else. The value comes from the erlang
        # library so the elixir typespec is wrong.
        {:error, :unsupported_value}
    end
  end

  def valid_key_id?(nil = _config_id, nil = _received_id), do: true

  def valid_key_id?(config_id, received_id) do
    config_id == received_id
  end
end
