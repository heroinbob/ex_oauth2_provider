defmodule ExOauth2Provider.Token.Utils.Response do
  @moduledoc false

  alias ExOauth2Provider.Config
  alias ExOauth2Provider.OpenId

  @doc false
  @spec response({:ok, map()} | {:error, map()}, keyword()) ::
          {:ok, map()} | {:error, map(), atom()}
  def response(
        {
          :ok,
          %{
            access_token: token,
            client: client
          } = context
        },
        config
      ) do
    token
    |> build_token_payload()
    |> maybe_include_id_token(context, config)
    |> customize_response(token, config)
    |> then(&{:ok, &1})
  end

  def response({:error, %{error: error, error_http_status: error_http_status}}, _config) do
    {:error, error, error_http_status}
  end

  # For DB errors
  def response({:error, %{error: error}}, _config) do
    {:error, error, :bad_request}
  end

  @doc false
  @spec revocation_response({:ok, map()} | {:error, map()}, keyword()) ::
          {:ok, map()} | {:error, map(), atom()}
  def revocation_response({:error, %{should_return_error: true} = params}, config) do
    response({:error, params}, config)
  end

  def revocation_response({_any, _params}, _config), do: {:ok, %{}}

  defp build_token_payload(access_token) do
    %{
      access_token: access_token.token,
      created_at: access_token.inserted_at,
      expires_in: access_token.expires_in,
      refresh_token: access_token.refresh_token,
      scope: access_token.scopes,
      # Access Token type: Bearer.
      # @see https://tools.ietf.org/html/rfc6750
      #   The OAuth 2.0 Authorization Framework: Bearer Token Usage
      token_type: "bearer"
    }
  end

  defp maybe_include_id_token(%{scope: scope} = access_token, context, config) do
    if OpenId.in_scope?(scope) do
      %{
        access_token: access_token,
        id_token: OpenId.generate_id_token(access_token, context, config)
      }
    else
      access_token
    end
  end

  defp customize_response(response_body, access_token, config) do
    case Config.access_token_response_body_handler(config) do
      {module, method} -> apply(module, method, [response_body, access_token])
      _ -> response_body
    end
  end
end
