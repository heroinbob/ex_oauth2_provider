defmodule ExOauth2Provider.Token.AuthorizationCode.RequestParams do
  @moduledoc """
  Context to make working with request params for the token flow easier.
  """
  alias ExOauth2Provider.PKCE
  alias ExOauth2Provider.Token.AuthorizationCode

  @doc """
  Return true if the given context has valid request params.
  """
  @spec valid?(context :: AuthorizationCode.context(), config :: list()) :: boolean()
  def valid?(context, config) when is_map(context) and is_list(config) do
    with true <- valid_pkce?(context, config) do
      valid_redirect_uri?(context)
    end
  end

  defp valid_pkce?(context, config) do
    is_required = PKCE.required?(config)
    (is_required and PKCE.valid?(context, config)) or not is_required
  end

  defp valid_redirect_uri?(%{
         request: %{"redirect_uri" => redirect_uri},
         access_grant: grant
       }) do
    grant.redirect_uri == redirect_uri
  end

  defp valid_redirect_uri?(_context), do: false
end
