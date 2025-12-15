defmodule ExOauth2Provider.Test.Fixtures do
  @moduledoc false

  alias ExOauth2Provider.{
    AccessTokens,
    Test.PKCE
  }

  alias Dummy.{
    OauthApplications.OauthApplication,
    OauthAccessGrants.OauthAccessGrant,
    OauthDeviceGrants.OauthDeviceGrant,
    Repo,
    Users.User
  }

  alias Ecto.Changeset

  @code_challenge_request_param_lookup %{
    plain: "plain",
    s256: "S256"
  }

  def resource_owner(attrs \\ []) do
    attrs = Keyword.merge([email: "foo@example.com"], attrs)

    User
    |> struct()
    |> Changeset.change(attrs)
    |> Repo.insert!()
  end

  def application(attrs \\ []) do
    resource_owner = Keyword.get(attrs, :resource_owner) || resource_owner()

    attrs =
      [
        owner_id: resource_owner.id,
        uid: "test",
        secret: "secret",
        name: "OAuth Application",
        redirect_uri: "urn:ietf:wg:oauth:2.0:oob",
        scopes: "public read write"
      ]
      |> Keyword.merge(attrs)
      |> Keyword.drop([:resource_owner])

    %OauthApplication{}
    |> Changeset.change(attrs)
    |> Repo.insert!()
  end

  def access_token(attrs \\ []) do
    {:ok, access_token} =
      attrs
      |> Keyword.get(:resource_owner)
      |> Kernel.||(resource_owner())
      |> AccessTokens.create_token(Enum.into(attrs, %{}), otp_app: :ex_oauth2_provider)

    access_token
  end

  def application_access_token(attrs \\ []) do
    {:ok, access_token} =
      attrs
      |> Keyword.get(:application)
      |> Kernel.||(application())
      |> AccessTokens.create_application_token(Enum.into(attrs, %{}),
        otp_app: :ex_oauth2_provider
      )

    access_token
  end

  def access_grant(application, user, code, redirect_uri) do
    attrs = [
      expires_in: 900,
      redirect_uri: "urn:ietf:wg:oauth:2.0:oob",
      application_id: application.id,
      resource_owner_id: user.id,
      token: code,
      scopes: "read",
      redirect_uri: redirect_uri
    ]

    %OauthAccessGrant{}
    |> Changeset.change(attrs)
    |> Repo.insert!()
  end

  def device_grant(attrs \\ []) do
    attrs =
      [
        device_code: "device-code",
        expires_in: 900,
        user_code: "user-code"
      ]
      |> Keyword.merge(attrs)

    %OauthDeviceGrant{}
    |> Changeset.change(attrs)
    |> Repo.insert!()
  end

  @doc """
  Veeeeeery basic. Override as needed. There is a default client and request
  but anything else you provide in is merged. So if you pass `:foo` then it'll
  be included. The default is a request with PKCE disabled and no PKCE info.

  ## Opts

  - `:client` - The OauthApplication to use.
  - `:request` - The request params
  - `:resource_owner` - The resource owner that made the request.
  """
  @spec authorization_request_context(opts :: list()) :: map()
  def authorization_request_context(opts \\ []) do
    opts = Map.new(opts)

    Map.merge(
      %{
        client: %OauthApplication{pkce: :disabled},
        request: %{},
        resource_owner: %{}
      },
      opts
    )
  end

  @doc """
  Generate an auth context with PKCE. Works the same as authorization_request_context/1
  except it also supports the options below. It's important to note that the PKCE request
  params are generated and provided so if you want something more custom you must pass in
  `:request` with what you want.

  ## Options

  - `:app_setting` - The pkce setting for the app. Default `:all_methods`
  - `:client` - Override the OauthApplication.
  - `:code_challenge` - The code challenge for the request param. Default is a generated
                        one that relies on the challenge method value `:code_challenge_method` option.
  - `:code_challenge_method` - The code chalenge method to use. Default is `:s256` but can also be `:plain`.
  - `:code_challenge_method_request_param` - The value to use for the request param for the code challenge
                                             method. Default is to convert the value of
                                             `:code_challenge_method`
  - `:request` - A custom request to use. When specified it'll override the generated one.
  """
  def authorization_request_context_with_pkce(opts \\ []) do
    {app_setting, opts} = Keyword.pop(opts, :app_setting, :all_methods)
    {challenge_method, opts} = Keyword.pop(opts, :code_challenge_method, :s256)

    {challenge, opts} =
      Keyword.pop(
        opts,
        :code_challenge,
        PKCE.generate_code_challenge(%{method: challenge_method})
      )

    {param, opts} =
      Keyword.pop(
        opts,
        :code_challenge_method_request_param,
        @code_challenge_request_param_lookup[challenge_method]
      )

    {request, opts} =
      Keyword.pop(
        opts,
        :request,
        %{
          "code_challenge" => challenge,
          "code_challenge_method" => param
        }
      )

    {client, opts} = Keyword.pop(opts, :client, %OauthApplication{pkce: app_setting})

    opts
    |> Keyword.merge(client: client, request: request)
    |> authorization_request_context()
  end

  @doc """
  Veeeeeery basic. Override as needed. There is a default client and request
  but anything else you provide in is merged. So if you pass `:foo` then it'll
  be included. The default is a request with PKCE disabled and no PKCE info.

  ## Opts

  - `:client` - The OauthApplication to use.
  - `:request` - The request params
  - `:resource_owner` - The resource owner that made the request.
  """
  @spec token_request_context(opts :: list()) :: map()
  def token_request_context(opts \\ []) do
    opts = Map.new(opts)

    Map.merge(
      %{
        access_grant: %OauthAccessGrant{},
        client: %OauthApplication{pkce: :disabled},
        request: %{},
        resource_owner: %User{}
      },
      opts
    )
  end

  @doc """
  Generate a token request context with PKCE fields. This is the same as
  token_request_context/1 but with additional options supported.

  ## Options

  - `:app_setting` - The app's pkce setting.
  - `:client` - The app's pkce setting.
  - `:code_challenge` - The code challenge for the access grant.
                        one that relies on the challenge method value `:code_challenge_method` option.
  - `:code_challenge_method` - The code chalenge method to use. Default is `:s256` but can also be `:plain`.
  - `:code_verifier` - The verifier to use in the validation.
  - `:request` - A custom request param map to pass if you wish to do something else.
  """
  def token_request_context_with_pkce(opts \\ []) do
    {app_setting, opts} = Keyword.pop(opts, :app_setting, :all_methods)
    {client, opts} = Keyword.pop(opts, :client, %OauthApplication{pkce: app_setting})
    {method, opts} = Keyword.pop(opts, :code_challenge_method, :s256)
    {verifier, opts} = Keyword.pop(opts, :code_verifier, PKCE.generate_code_verifier())

    {challenge, opts} =
      Keyword.pop(opts, :code_challenge, PKCE.generate_code_challenge(verifier, method))

    {request, opts} = Keyword.pop(opts, :request, %{"code_verifier" => verifier})

    {grant, opts} =
      Keyword.pop(opts, :access_grant, %OauthAccessGrant{
        code_challenge: challenge,
        code_challenge_method: method
      })

    opts
    |> Keyword.merge(access_grant: grant, client: client, request: request)
    |> token_request_context()
  end
end
