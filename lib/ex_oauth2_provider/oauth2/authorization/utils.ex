defmodule ExOauth2Provider.Authorization.Utils do
  @moduledoc false

  alias ExOauth2Provider.{
    Applications,
    OpenId,
    Utils.Error
  }

  alias Ecto.Schema

  # TODO: This should be a struct
  @type context :: %{
          required(:client) => map(),
          required(:is_open_id) => boolean(),
          required(:request) => map(),
          required(:resource_owner) => map(),
          optional(:access_token) => map()
        }

  @doc false
  @spec prehandle_request(
          Schema.t() | nil,
          map(),
          keyword()
        ) :: {:ok, context()} | {:error, map()}
  def prehandle_request(resource_owner, request, config, opts \\ []) do
    resource_owner
    |> new_params(request)
    |> load_client(config, opts)
    |> set_defaults()
  end

  defp new_params(resource_owner, request) do
    {:ok, %{resource_owner: resource_owner, request: request}}
  end

  defp load_client({:ok, %{request: %{"client_id" => client_id}} = params}, config, opts) do
    case Applications.get_application(client_id, config) do
      nil -> Error.add_error({:ok, params}, Error.invalid_client(opts))
      client -> {:ok, Map.put(params, :client, client)}
    end
  end

  defp load_client({:ok, params}, _config, _opts),
    do: Error.add_error({:ok, params}, Error.invalid_request())

  defp set_defaults({:error, params}), do: {:error, params}

  defp set_defaults({:ok, %{request: request, client: client} = params}) do
    [redirect_uri | _rest] = String.split(client.redirect_uri)

    request =
      Map.new()
      |> Map.put("redirect_uri", redirect_uri)
      |> Map.put("scope", nil)
      |> Map.merge(request)

    scope = Map.fetch!(request, "scope")

    {
      :ok,
      Map.merge(
        params,
        %{is_open_id: OpenId.in_scope?(scope), request: request}
      )
    }
  end
end
