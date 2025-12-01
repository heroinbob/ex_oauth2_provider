defmodule ExOauth2Provider.Authorization.Code.RequestParams do
  @moduledoc """
  Logic for working with authorization code request params.
  """
  alias ExOauth2Provider.{
    Authorization,
    Config,
    PKCE,
    RedirectURI,
    Scopes
  }

  @doc """
  Build a map of params for creating an access grant.
  """
  def to_access_grant_params(request, config) do
    request
    |> Map.take(~w[redirect_uri scope])
    |> Map.new(fn {k, v} ->
      case k do
        "redirect_uri" -> {:redirect_uri, v}
        "scope" -> {:scopes, v}
      end
    end)
    |> Map.put(:expires_in, Config.authorization_code_expires_in(config))
    |> maybe_include_pkce(request, config)
  end

  defp maybe_include_pkce(attrs, request, config) do
    pkce_attrs =
      if PKCE.required?(config) do
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
             | :invalid_scopes
             | :invalid_pkce}
  def validate(context, config) do
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

  defp validate_scopes(%{request: %{"scope" => scopes}, client: client} = _context, config) do
    scopes = Scopes.to_list(scopes)

    server_scopes =
      client.scopes
      |> Scopes.to_list()
      |> Scopes.default_to_server_scopes(config)

    case Scopes.all?(server_scopes, scopes) do
      true -> :ok
      false -> {:error, :invalid_scopes}
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

  defp validate_pkce(%{request: request} = _context, config) do
    is_required = PKCE.required?(config)

    cond do
      is_required and PKCE.valid?(request, config) -> :ok
      not is_required -> :ok
      true -> {:error, :invalid_pkce}
    end
  end
end
