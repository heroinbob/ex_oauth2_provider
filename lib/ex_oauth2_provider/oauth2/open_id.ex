defmodule ExOauth2Provider.OpenId do
  @moduledoc """
  Logic to allow working with Open ID.
  """
  alias ExOauth2Provider.AccessTokens.AccessToken
  alias ExOauth2Provider.OpenId.OpenIdConfig
  alias ExOauth2Provider.OpenId.IdToken
  alias ExOauth2Provider.Scopes

  @type id_token :: %{
          required(:aud) => String.t(),
          required(:exp) => non_neg_integer(),
          required(:iat) => non_neg_integer(),
          required(:iss) => String.t(),
          required(:sub) => String.t(),
          optional(:auth_time) => non_neg_integer(),
          optional(:email) => String.t(),
          optional(:email_verified) => boolean(),
          optional(:nonce) => String.t()
        }

  @open_id_scope "openid"

  @spec fetch_nonce(request_params :: map()) :: {:ok, String.t()} | :not_found
  def fetch_nonce(request_params) do
    case request_params do
      %{"nonce" => nonce} -> {:ok, nonce}
      _ -> :not_found
    end
  end

  @spec generate_id_token(
          access_token :: AccessToken.t(),
          context :: map(),
          config :: keyword()
        ) :: id_token()
  def generate_id_token(access_token, context, config) do
    IdToken.new(access_token, context, config)
  end

  @spec in_scope?(scopes :: [String.t()] | String.t()) :: boolean()
  def in_scope?(scopes) when is_binary(scopes) do
    scopes
    |> Scopes.to_list()
    |> in_scope?()
  end

  def in_scope?(scopes) when is_list(scopes), do: @open_id_scope in scopes

  def in_scope?(_), do: false

  @doc """
  Sign the given ID token. This relies on the configured signing_key,
  algorithm and key ID. See OpenIdConfig for more info.
  """
  @spec sign_id_token(id_token :: id_token(), opts :: keyword()) ::
          {:ok, String.t()} | {:error, any()}
  def sign_id_token(%{iss: _} = id_token, opts \\ []) do
    %{
      id_token_signing_key: signing_key,
      id_token_signing_key_algorithm: algorithm,
      id_token_signing_key_id: key_id
    } = OpenIdConfig.get(opts)

    header = build_signing_header(algorithm, key_id)

    {_, compact_jws} =
      signing_key
      |> JOSE.JWT.sign(header, id_token)
      |> JOSE.JWS.compact()

    {:ok, compact_jws}
  rescue
    error -> {:error, error}
  end

  defp build_signing_header(algorithm, key_id) do
    header = %{"alg" => algorithm, "typ" => "JWT"}

    if is_binary(key_id) do
      Map.put(header, "kid", key_id)
    else
      header
    end
  end
end
