defmodule ExOauth2Provider.Plug.ClientSecretBasic do
  @moduledoc """
  A simple plug to extract the client ID and secret out
  of the request headers.

  The default behavior is to extract client ID and secret and then assign
  them for your own use. If the values can't be determined then plug halts
  execution and responds with `401` and an unauthenticated error.

  You can change this behavior by setting the options when you use it. See
  below.

  ## Options

  You can pass a keyword or a map of options.

  `:on_error` - Define what to do when the values can't be determined. Must
                be one of `:deny_access` or `:noop`. Default is `:deny_access`.
  """
  @behaviour Plug

  import Plug.Conn

  alias ExOauth2Provider.Plug.ErrorHandler

  @impl Plug
  def call(%Plug.Conn{req_headers: headers} = conn, opts) do
    case Enum.find_value(
           headers,
           fn {k, v} -> if k == "authorization", do: v end
         ) do
      "Basic " <> encoded -> decode_authorization(encoded, conn, opts)
      _ -> deny_access(conn, opts)
    end
  end

  @impl Plug
  def init(opts) when is_map(opts), do: opts
  def init(opts) when is_list(opts), do: Map.new(opts)

  defp decode_authorization(encoded, conn, opts) do
    case Base.decode64(encoded) do
      {:ok, decoded} -> extract_id_and_secret(decoded, conn, opts)
      _ -> deny_access(conn, opts)
    end
  end

  defp extract_id_and_secret(value, conn, opts) do
    case String.split(value, ":") do
      [id, secret] ->
        conn
        |> assign(:client_id, id)
        |> assign(:client_secret, secret)

      _ ->
        deny_access(conn, opts)
    end
  end

  defp deny_access(conn, %{on_error: :noop}), do: conn

  defp deny_access(conn, _opts) do
    conn
    |> halt()
    |> ErrorHandler.unauthenticated(%{})
  end
end
