defmodule ExOauth2Provider.Authorization.Code.RequestParams do
  @moduledoc """
  Logic for working with authorization code request params.
  """
  alias ExOauth2Provider.{
    Authorization,
    Config,
    OpenId,
    PKCE,
    RedirectURI,
    Scopes
  }

  @doc """
  Build a map of params for creating an access grant. PKCE is included depending
  on the client pkce setting or the config. The first param is the request
  params.

  ## Config

  - `:client` - You can specify the client which will have it's PKCE setting taken into
                account in addition to the application config.
  """
  @spec to_access_grant_params(context :: Authorization.context(), config :: list()) :: map()
  def to_access_grant_params(%{request: request} = context, config) do
    request
    |> Map.take(~w[redirect_uri scope])
    |> Map.new(fn {k, v} ->
      case k do
        "redirect_uri" -> {:redirect_uri, v}
        "scope" -> {:scopes, v}
      end
    end)
    |> Map.put(:expires_in, Config.authorization_code_expires_in(config))
    |> maybe_add_open_id_nonce(context)
    |> maybe_add_pkce(context, config)
  end

  defp maybe_add_open_id_nonce(
         %{scopes: scopes} = attrs,
         %{request: request_params} = _context
       ) do
    nonce = Map.get(request_params, "nonce")

    if OpenId.in_scope?(scopes) and is_binary(nonce) do
      Map.put(attrs, :open_id_nonce, nonce)
    else
      attrs
    end
  end

  defp maybe_add_open_id_nonce(attrs, _context), do: attrs

  defp maybe_add_pkce(attrs, %{request: request} = context, config) do
    pkce_attrs =
      if PKCE.required?(context, config) do
        %{
          code_challenge: request["code_challenge"],
          code_challenge_method: request["code_challenge_method"]
        }
      else
        %{}
      end

    Map.merge(attrs, pkce_attrs)
  end

  @doc """
  Validate the given context to ensure it is a valid authorization request.
  """
  @spec validate(context :: Authorization.context(), config :: list()) ::
          :ok
          | {:error,
             :invalid_request
             | :invalid_resource_owner
             | :invalid_redirect_uri
             | :invalid_pkce
             | :invalid_scopes}
  def validate(context, config) do
    # Remember - client ID is validated and set in the contexts as the first step
    # in the flow. So it's guaranteed if this is called.
    with :ok <- validate_resource_owner(context),
         :ok <- validate_redirect_uri(context, config),
         :ok <- validate_scopes(context, config) do
      validate_pkce(context, config)
    end
  end

  defp validate_resource_owner(%{resource_owner: resource_owner} = _context) do
    case resource_owner do
      %{__struct__: _} -> :ok
      _ -> {:error, :invalid_resource_owner}
    end
  end

  defp validate_scopes(
         %{
           is_open_id: is_open_id,
           request: request,
           client: client
         } = _context,
         config
       ) do
    request_scopes = Scopes.from(request)
    client_scopes = Scopes.from(client, config)

    if Scopes.all?(client_scopes, request_scopes) and
         open_id_safe?(is_open_id, request_scopes) do
      :ok
    else
      {:error, :invalid_scopes}
    end
  end

  defp validate_redirect_uri(
         %{request: %{"redirect_uri" => redirect_uri}, client: client} = _context,
         config
       ) do
    cond do
      RedirectURI.native_redirect_uri?(redirect_uri, config) ->
        :ok

      RedirectURI.valid_for_authorization?(redirect_uri, client.redirect_uri, config) ->
        :ok

      true ->
        {:error, :invalid_redirect_uri}
    end
  end

  defp validate_redirect_uri(_context, _config), do: {:error, :invalid_request}

  defp validate_pkce(context, config) do
    is_required = PKCE.required?(context, config)

    cond do
      is_required and PKCE.valid?(context, config) -> :ok
      not is_required -> :ok
      true -> {:error, :invalid_pkce}
    end
  end

  defp open_id_safe?(is_open_id, request_scopes) do
    in_request = OpenId.in_scope?(request_scopes)

    if is_open_id do
      in_request
    else
      not in_request
    end
  end
end
