defmodule ExOauth2Provider.Authorization.Utils.Response do
  @moduledoc false

  alias Ecto.Schema

  alias ExOauth2Provider.{
    OpenId,
    RedirectURI,
    Scopes,
    Utils
  }

  @type authorization_success :: {:ok, map()}
  @type device_authorization_success :: {:ok, Schema.t()}
  @type device_preauthorization_success :: {:ok, map()}
  @type error :: {:error, map(), integer()}
  @type native_redirect :: {:native_redirect, %{code: binary()}}

  @type preauthorization_success :: {
          :ok,
          %{
            required(:app) => Schema.t(),
            required(:scopes) => [String.t()],
            optional(:nonce) => String.t()
          }
        }

  @type redirect :: {:redirect, binary()}

  @doc false
  @spec error_response({:error, map()}, keyword()) :: error() | redirect() | native_redirect()
  def error_response({:error, %{error: error} = params}, config) do
    build_response(params, error, config)
  end

  @doc false
  @spec preauthorize_response({:ok, map()} | {:error, map()}, keyword()) ::
          preauthorization_success() | error() | redirect() | native_redirect()
  def preauthorize_response({:ok, %{grant: grant} = params}, config) do
    build_response(params, %{code: grant.token}, config)
  end

  def preauthorize_response(
        {
          :ok,
          %{
            client: client,
            is_open_id: is_open_id,
            request: %{"scope" => scopes} = request
          }
        },
        _config
      ) do
    {
      :ok,
      add_open_id_nonce(
        is_open_id,
        %{app: client, scopes: Scopes.to_list(scopes)},
        request
      )
    }
  end

  def preauthorize_response({:error, %{error: error} = params}, config) do
    build_response(params, error, config)
  end

  defp add_open_id_nonce(true = _is_open_id, payload, request) do
    case OpenId.fetch_nonce(request) do
      {:ok, nonce} -> Map.put(payload, :nonce, nonce)
      _not_found -> payload
    end
  end

  defp add_open_id_nonce(_is_open_id, payload, _request), do: payload

  @doc false
  @spec authorize_response({:ok, map()} | {:error, map()}, keyword()) ::
          authorization_success() | error() | redirect() | native_redirect()
  def authorize_response({:ok, %{grant: grant} = params}, config) do
    build_response(params, %{code: grant.token}, config)
  end

  def authorize_response({:error, %{error: error} = params}, config) do
    build_response(params, error, config)
  end

  @doc false
  @spec deny_response({:error, map()}, keyword()) :: error() | redirect() | native_redirect()
  def deny_response({:error, %{error: error} = params}, config) do
    build_response(params, error, config)
  end

  defp build_response(%{request: request} = params, payload, config) do
    payload = add_state(payload, request)

    case can_redirect?(params, config) do
      true -> build_redirect_response(params, payload, config)
      _ -> build_standard_response(params, payload)
    end
  end

  defp add_state(payload, request) do
    case request["state"] do
      nil ->
        payload

      state ->
        %{"state" => state}
        |> Map.merge(payload)
        |> Utils.remove_empty_values()
    end
  end

  defp build_redirect_response(%{request: %{"redirect_uri" => redirect_uri}}, payload, config) do
    case RedirectURI.native_redirect_uri?(redirect_uri, config) do
      true -> {:native_redirect, payload}
      _ -> {:redirect, RedirectURI.uri_with_query(redirect_uri, payload)}
    end
  end

  defp build_standard_response(%{grant: _}, payload) do
    {:ok, payload}
  end

  defp build_standard_response(%{error: error, error_http_status: error_http_status}, _) do
    {:error, error, error_http_status}
  end

  # For DB errors
  defp build_standard_response(%{error: error}, _) do
    {:error, error, :bad_request}
  end

  defp can_redirect?(%{error: %{error: :invalid_redirect_uri}}, _config), do: false
  defp can_redirect?(%{error: %{error: :invalid_client}}, _config), do: false

  defp can_redirect?(
         %{error: %{error: _error}, request: %{"redirect_uri" => redirect_uri}},
         config
       ),
       do: !RedirectURI.native_redirect_uri?(redirect_uri, config)

  defp can_redirect?(%{error: _}, _config), do: false
  defp can_redirect?(%{request: %{}}, _config), do: true
end
