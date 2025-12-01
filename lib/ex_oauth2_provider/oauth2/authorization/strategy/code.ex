defmodule ExOauth2Provider.Authorization.Code do
  @moduledoc """
  Methods for authorization code flow.

  The flow consists of three method calls:

  1. `preauthorize(resource_owner, request)`

  This validates the request. If a resource owner already have been
  authenticated previously it'll respond with a redirect tuple.

  2. `authorize(resource_owner, request)`

  This confirms a resource owner authorization, and will generate an access
  token.

  3. `deny(resource_owner, request)`

  This rejects a resource owner authorization.

  ---

  In a controller it could look like this:

  ```elixir
  alias ExOauth2Provider.Authorization

  def new(conn, params) do
    case Authorization.preauthorize(current_resource_owner(conn), params) do
      {:ok, client, scopes} ->
        render(conn, "new.html", params: params, client: client, scopes: scopes)
      {:native_redirect, %{code: code}} ->
        redirect(conn, to: oauth_authorization_path(conn, :show, code))
      {:redirect, redirect_uri} ->
        redirect(conn, external: redirect_uri)
      {:error, error, status} ->
        conn
        |> put_status(status)
        |> render("error.html", error: error)
    end
  end

  def create(conn, params) do
    conn
    |> current_resource_owner
    |> Authorization.authorize(params)
    |> redirect_or_render(conn)
  end

  def delete(conn, params) do
    conn
    |> current_resource_owner
    |> Authorization.deny(params)
    |> redirect_or_render(conn)
  end
  ```
  """
  alias ExOauth2Provider.{
    Config,
    AccessTokens,
    AccessGrants,
    Authorization.Code.RequestParams,
    Authorization.Utils,
    Authorization.Utils.Response,
    Utils.Error
  }

  alias Ecto.Schema

  @error_lookup %{
    invalid_redirect_uri: Error.invalid_redirect_uri(),
    invalid_scopes: Error.invalid_scopes()
  }

  @doc """
  Validates an authorization code flow request.

  Will check if there's already an existing access token with same scope and client
  for the resource owner.

  ## Example
      resource_owner
      |> ExOauth2Provider.Authorization.preauthorize(%{
        "client_id" => "Jf5rM8hQBc",
        "response_type" => "code"
      }, otp_app: :my_app)

  ## Response
      {:ok, client, scopes}                                         # Show request page with client and scopes
      {:error, %{error: error, error_description: _}, http_status}  # Show error page with error and http status
      {:redirect, redirect_uri}                                     # Redirect
      {:native_redirect, %{code: code}}                             # Redirect to :show page
  """
  @spec preauthorize(Schema.t(), map(), keyword()) ::
          Response.preauthorization_success()
          | Response.error()
          | Response.redirect()
          | Response.native_redirect()
  def preauthorize(resource_owner, request, config \\ []) do
    resource_owner
    |> Utils.prehandle_request(request, config)
    |> validate_request(config)
    |> check_previous_authorization(config)
    |> reissue_grant(config)
    |> skip_authorization_if_applicable(config)
    |> Response.preauthorize_response(config)
  end

  defp check_previous_authorization({:error, params}, _config), do: {:error, params}

  defp check_previous_authorization(
         {:ok,
          %{resource_owner: resource_owner, client: application, request: %{"scope" => scopes}} =
            params},
         config
       ) do
    case AccessTokens.get_token_for(resource_owner, application, scopes, config) do
      nil -> {:ok, params}
      token -> {:ok, Map.put(params, :access_token, token)}
    end
  end

  defp reissue_grant({:error, params}, _config), do: {:error, params}

  defp reissue_grant({:ok, %{access_token: _access_token} = params}, config) do
    issue_grant({:ok, params}, config)
  end

  defp reissue_grant({:ok, params}, _config), do: {:ok, params}

  defp skip_authorization_if_applicable({:error, _params} = error, _config), do: error

  defp skip_authorization_if_applicable({:ok, %{grant: _grant}} = payload, _config), do: payload

  defp skip_authorization_if_applicable({:ok, params}, config) do
    %{client: application, resource_owner: user} = params

    case Config.skip_authorization(config).(user, application) do
      true -> issue_grant({:ok, params}, config)
      false -> {:ok, params}
    end
  end

  @doc """
  Authorizes an authorization code flow request.

  This is used when a resource owner has authorized access. If successful,
  this will generate an access token grant.

  ## Example
      resource_owner
      |> ExOauth2Provider.Authorization.authorize(%{
        "client_id" => "Jf5rM8hQBc",
        "response_type" => "code",
        "scope" => "read write",                  # Optional
        "state" => "46012",                       # Optional
        "redirect_uri" => "https://example.com/"  # Optional
      }, otp_app: :my_app)

  ## Response
      {:ok, code}                                                  # A grant was generated
      {:error, %{error: error, error_description: _}, http_status} # Error occurred
      {:redirect, redirect_uri}                                    # Redirect
      {:native_redirect, %{code: code}}                            # Redirect to :show page
  """
  @spec authorize(Schema.t(), map(), keyword()) ::
          Response.authorization_success()
          | Response.error()
          | Response.redirect()
          | Response.native_redirect()
  def authorize(resource_owner, request, config \\ []) do
    resource_owner
    |> Utils.prehandle_request(request, config)
    |> validate_request(config)
    |> issue_grant(config)
    |> Response.authorize_response(config)
  end

  defp issue_grant({:error, %{error: _error} = params}, _config), do: {:error, params}

  defp issue_grant(
         {:ok, %{resource_owner: resource_owner, client: application, request: request} = params},
         config
       ) do
    grant_params = RequestParams.to_access_grant_params(request, config)

    case AccessGrants.create_grant(resource_owner, application, grant_params, config) do
      {:ok, grant} ->
        {:ok, Map.put(params, :grant, grant)}

      {:error, error} ->
        Error.add_error({:ok, params}, error)
    end
  end

  @doc """
  Rejects an authorization code flow request.

  This is used when a resource owner has rejected access.

  ## Example
      resource_owner
      |> ExOauth2Provider.Authorization.deny(%{
        "client_id" => "Jf5rM8hQBc",
        "response_type" => "code"
      }, otp_app: :my_app)

  ## Response type
      {:error, %{error: error, error_description: _}, http_status} # Error occurred
      {:redirect, redirect_uri}                                    # Redirect
  """
  @spec deny(Schema.t(), map(), keyword()) :: Response.error() | Response.redirect()
  def deny(resource_owner, request, config \\ []) do
    resource_owner
    |> Utils.prehandle_request(request, config)
    |> validate_request(config)
    |> Error.add_error(Error.access_denied())
    |> Response.deny_response(config)
  end

  defp validate_request({:error, _} = error, _config), do: error

  defp validate_request({:ok, params}, config) do
    case RequestParams.validate(params, config) do
      :ok ->
        {:ok, params}

      {:error, error} ->
        Error.add_error(
          {:ok, params},
          Map.get(@error_lookup, error, Error.invalid_request())
        )
    end
  end
end
