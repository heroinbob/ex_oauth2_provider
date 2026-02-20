defmodule ExOauth2Provider.Token.AuthorizationCode.RequestParams do
  @moduledoc """
  Context to make working with request params for the token flow easier.
  """
  alias ExOauth2Provider.OpenId
  alias ExOauth2Provider.PKCE
  alias ExOauth2Provider.Scopes
  alias ExOauth2Provider.Token.AuthorizationCode

  @doc """
  Return true if the given context has valid request params.
  """
  @spec valid?(context :: AuthorizationCode.context(), config :: list()) :: boolean()
  def valid?(context, config) when is_map(context) and is_list(config) do
    # NOTE: client_id is already validated because we load the client in the first
    # step of the flow. The code field is validated because we also load the grant
    # using the code and client_id. grant_type was used to determine the flow so
    # all that is left is redirect_uri, PKCE and OpenID.
    with true <- valid_redirect_uri?(context),
         true <- valid_scopes?(context, config) do
      valid_pkce?(context, config)
    end
  end

  defp valid_pkce?(context, config) do
    is_required = PKCE.required?(context, config)
    (is_required and PKCE.valid?(context, config)) or not is_required
  end

  defp valid_redirect_uri?(%{
         request: %{"redirect_uri" => redirect_uri},
         access_grant: grant
       }) do
    grant.redirect_uri == redirect_uri
  end

  defp valid_redirect_uri?(_context), do: false

  # When OpenID is used then the grant scopes must also contain OpenID.
  # Otherwise the grant must NOT be for an OpenID request.
  defp valid_scopes?(%{access_grant: grant, client: client} = _context, config) do
    in_grant = grant |> Scopes.from() |> OpenId.in_scope?()
    client_scopes = Scopes.from(client, config)

    if OpenId.in_scope?(client_scopes) do
      in_grant
    else
      not in_grant
    end
  end
end
