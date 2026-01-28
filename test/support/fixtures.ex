defmodule ExOauth2Provider.Test.Fixtures do
  @moduledoc false

  use ExMachina.Ecto, repo: Dummy.Repo

  alias ExOauth2Provider.{
    OpenId.Claim,
    Test.OpenId,
    Test.PKCE,
    Utils
  }

  alias Dummy.{
    OauthApplications.OauthApplication,
    OauthAccessGrants.OauthAccessGrant,
    OauthDeviceGrants.OauthDeviceGrant,
    OauthAccessTokens.OauthAccessToken,
    Users.User
  }

  @code_challenge_request_param_lookup %{
    plain: "plain",
    s256: "S256"
  }

  def access_grant_factory do
    %OauthAccessGrant{
      application: build(:application),
      expires_in: 900,
      redirect_uri: "urn:ietf:wg:oauth:2.0:oob",
      resource_owner: build(:user),
      scopes: "read",
      token: Utils.generate_token()
    }
  end

  def access_token_factory do
    %OauthAccessToken{
      application: build(:application),
      expires_in: 300,
      previous_refresh_token: "",
      refresh_token: nil,
      resource_owner: build(:user),
      revoked_at: nil,
      scopes: "public read write",
      token: Utils.generate_token()
    }
  end

  def application_factory do
    %OauthApplication{
      name: "OAuth Application",
      owner: build(:user),
      redirect_uri: "urn:ietf:wg:oauth:2.0:oob",
      scopes: "public read write",
      secret: Ecto.UUID.generate(),
      uid: Ecto.UUID.generate()
    }
  end

  def device_grant_factory do
    %OauthDeviceGrant{
      application: build(:application),
      device_code: "device-code",
      expires_in: 900,
      resource_owner: build(:user),
      user_code: "user-code"
    }
  end

  def open_id_claim_factory do
    %Claim{name: :test}
  end

  def private_rs256_key_factory do
    # Generated via the following command
    # ssh-keygen -t rsa -b 4096 -m PEM -E SHA256 -f test/support/open_id/rsa256_key.pem
    # There is no passphrase.
    OpenId.get_config()
    |> Map.fetch!(:id_token_signing_key_pem)
    |> JOSE.JWK.from_pem()
  end

  def user_factory do
    %User{email: "ima@user.com"}
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
    client = Keyword.get(opts, :client, %OauthApplication{pkce: :disabled})
    request = Keyword.get(opts, :request, %{})
    opts = Map.new(opts)

    Map.merge(
      %{
        client: client,
        is_open_id: false,
        request: request,
        resource_owner: build(:user)
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

  - `:access_grant` - The OauthAccessGrant to use.
  - `:client` - The OauthApplication to use.
  - `:request` - The request params
  - `:resource_owner` - The resource owner that made the request.
  """
  @spec token_request_context(opts :: list()) :: map()
  def token_request_context(opts \\ []) do
    opts = Map.new(opts)

    Map.merge(
      %{
        access_grant: build(:access_grant),
        client: build(:application, pkce: :disabled),
        request: %{},
        resource_owner: build(:user)
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
