defmodule ExOauth2Provider.OpenId do
  @moduledoc """
  Logic to allow working with Open ID.
  """
  alias ExOauth2Provider.AccessTokens.AccessToken
  alias ExOauth2Provider.OpenId.Claim
  alias ExOauth2Provider.OpenId.EndSessionParams
  alias ExOauth2Provider.OpenId.OpenIdConfig
  alias ExOauth2Provider.OpenId.IdToken
  alias ExOauth2Provider.OpenId.Signatures
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

  @doc """
  End the current session for the given user based on the request params. If the given
  ID Token is valid then we revoke all access tokens for the user that are associated
  to the application that issued the token. Users must re-authenticate after this.

  See [OpenID documentation](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#toc)
  for more information.
  """
  @spec end_session(request_params :: map(), opts :: keyword()) ::
          :ok | {:ok, {:redirect, String.t()}} | {:error, any()}
  def end_session(request_params, opts) do
    open_id_config = get_config(opts)

    with {:ok, params} <-
           EndSessionParams.parse_request_params(
             request_params,
             open_id_config,
             opts
           ) do
      %EndSessionParams{
        post_logout_redirect_uri: redirect_uri,
        state: state
      } = params

      if is_binary(redirect_uri) do
        redirect_uri = add_state_to_redirect_uri(redirect_uri, state)
        {:ok, {:redirect, redirect_uri}}
      else
        :ok
      end
    end
  end

  defp add_state_to_redirect_uri(redirect_uri, nil = _state) do
    redirect_uri
  end

  defp add_state_to_redirect_uri(redirect_uri, state) do
    prefix = if String.contains?(redirect_uri, "?"), do: "&", else: "?"
    redirect_uri <> "#{prefix}state=#{state}"
  end

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

  defdelegate get_config(opts), to: OpenIdConfig, as: :get

  @spec in_scope?(scopes :: [String.t()] | String.t()) :: boolean()
  def in_scope?(scopes) when is_binary(scopes) do
    scopes
    |> Scopes.to_list()
    |> in_scope?()
  end

  def in_scope?(scopes) when is_list(scopes), do: @open_id_scope in scopes

  def in_scope?(_), do: false

  def list_claims(%OpenIdConfig{claims: claims}) do
    Enum.flat_map(
      claims,
      fn %Claim{includes: includes, name: name} ->
        [name | Enum.map(includes, & &1.name)]
      end
    )
  end

  def get_public_key(%OpenIdConfig{id_token_signing_key: key}) do
    key
    |> JOSE.JWK.to_public()
    |> JOSE.JWK.to_map()
    |> elem(1)
  end

  @doc """
  Sign the given ID token. This relies on the configured signing_key,
  algorithm and key ID. See OpenIdConfig for more info.
  """
  @spec sign_id_token!(id_token :: id_token(), opts :: keyword()) :: String.t()
  def sign_id_token!(%{iss: _} = id_token, opts) do
    Signatures.create!(id_token, opts)
  end
end
