defmodule ExOauth2Provider.Authorization.CodeTest do
  use ExOauth2Provider.TestCase

  alias Ecto.Changeset
  alias ExOauth2Provider.{Authorization, Config, Scopes}
  alias ExOauth2Provider.Test.{Fixtures, PKCE, QueryHelpers}

  alias Dummy.{
    OauthApplications.OauthApplication,
    OauthAccessGrants.OauthAccessGrant,
    Repo
  }

  @config [otp_app: :ex_oauth2_provider]
  @client_id "Jf5rM8hQBc"
  @valid_request %{
    "client_id" => @client_id,
    "response_type" => "code",
    "scope" => "app:read app:write"
  }
  @invalid_request %{
    error: :invalid_request,
    error_description:
      "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
  }
  @invalid_client %{
    error: :invalid_client,
    error_description:
      "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
  }
  @invalid_scope %{
    error: :invalid_scope,
    error_description: "The requested scope is invalid, unknown, or malformed."
  }
  @invalid_redirect_uri %{
    error: :invalid_redirect_uri,
    error_description: "The redirect uri included is not valid."
  }
  @access_denied %{
    error: :access_denied,
    error_description: "The resource owner or authorization server denied the request."
  }

  setup do
    %{owner: resource_owner} =
      application =
      Fixtures.insert(
        :application,
        uid: @client_id,
        scopes: "app:read app:write"
      )

    {:ok, %{resource_owner: resource_owner, application: application}}
  end

  describe "#preauthorize/3" do
    test "error when no resource owner" do
      assert Authorization.preauthorize(nil, @valid_request, @config) ==
               {:error, @invalid_request, :bad_request}
    end

    test "error when no client_id", %{resource_owner: resource_owner} do
      request = Map.delete(@valid_request, "client_id")

      assert Authorization.preauthorize(resource_owner, request, @config) ==
               {:error, @invalid_request, :bad_request}
    end

    test "error when invalid client", %{resource_owner: resource_owner} do
      request = Map.merge(@valid_request, %{"client_id" => "invalid"})

      assert Authorization.preauthorize(resource_owner, request, @config) ==
               {:error, @invalid_client, :unprocessable_entity}
    end

    test "works with a valid request", %{
      resource_owner: resource_owner,
      application: %{id: app_id}
    } do
      expected_scopes = Scopes.to_list(@valid_request["scope"])

      assert {
               :ok,
               %{
                 app: %OauthApplication{id: ^app_id},
                 scopes: ^expected_scopes
               }
             } = Authorization.preauthorize(resource_owner, @valid_request, @config)
    end

    test "when previous access token with different application scopes", %{
      resource_owner: resource_owner,
      application: %{id: app_id} = application
    } do
      access_token =
        Fixtures.insert(
          :access_token,
          resource_owner: resource_owner,
          application: application,
          scopes: "app:read"
        )

      expected_scopes = Scopes.to_list(@valid_request["scope"])

      assert {
               :ok,
               %{
                 app: %OauthApplication{id: ^app_id},
                 scopes: ^expected_scopes
               }
             } = Authorization.preauthorize(resource_owner, @valid_request, @config)

      QueryHelpers.change!(access_token, scopes: "app:read app:write")
      request = Map.merge(@valid_request, %{"scope" => "app:read"})
      expected_scopes = Scopes.to_list(request["scope"])

      assert {
               :ok,
               %{
                 app: %OauthApplication{id: ^app_id},
                 scopes: ^expected_scopes
               }
             } = Authorization.preauthorize(resource_owner, request, @config)
    end

    test "with limited scope", %{
      resource_owner: resource_owner,
      application: %{id: app_id}
    } do
      request = Map.merge(@valid_request, %{"scope" => "app:read"})

      assert {
               :ok,
               %{
                 app: %OauthApplication{id: ^app_id},
                 scopes: ["app:read"]
               }
             } = Authorization.preauthorize(resource_owner, request, @config)
    end

    test "error when invalid scope", %{resource_owner: resource_owner} do
      request = Map.merge(@valid_request, %{"scope" => "app:invalid"})

      assert Authorization.preauthorize(resource_owner, request, @config) ==
               {:error, @invalid_scope, :unprocessable_entity}
    end
  end

  describe "preauthorize/3 when openid is in scope and nonce is present" do
    test "it returns the nonce" do
      %{id: app_id} = app = Fixtures.insert(:application, scopes: "openid test")
      nonce = "ima-cute-lil-nonce"

      request =
        Map.merge(
          @valid_request,
          %{"client_id" => app.uid, "nonce" => nonce, "scope" => app.scopes}
        )

      assert {
               :ok,
               %{
                 app: %OauthApplication{id: ^app_id},
                 nonce: ^nonce,
                 scopes: ~w[openid test]
               }
             } = Authorization.preauthorize(app.owner, request, @config)
    end
  end

  describe "#preauthorize/3 when application has no scope" do
    setup %{resource_owner: resource_owner, application: application} do
      application = QueryHelpers.change!(application, scopes: "")

      %{resource_owner: resource_owner, application: application}
    end

    test "with limited server scope", %{
      resource_owner: resource_owner,
      application: %{id: app_id}
    } do
      request = Map.merge(@valid_request, %{"scope" => "read"})

      assert {:ok, %{app: %OauthApplication{id: ^app_id}, scopes: ["read"]}} =
               Authorization.preauthorize(resource_owner, request, @config)
    end

    test "error when invalid server scope", %{resource_owner: resource_owner} do
      request = Map.merge(@valid_request, %{"scope" => "invalid"})

      assert Authorization.preauthorize(resource_owner, request, @config) ==
               {:error, @invalid_scope, :unprocessable_entity}
    end
  end

  describe "#preauthorize/3 when previous access token with same scopes" do
    test "returns an access grant", %{
      resource_owner: resource_owner,
      application: application
    } do
      Fixtures.insert(
        :access_token,
        resource_owner: resource_owner,
        application: application,
        scopes: @valid_request["scope"]
      )

      assert {:native_redirect, %{code: code}} =
               Authorization.preauthorize(
                 resource_owner,
                 @valid_request,
                 otp_app: :ex_oauth2_provider
               )

      access_grant = QueryHelpers.get_latest_inserted(OauthAccessGrant)

      assert code == access_grant.token
    end
  end

  describe "#preauthorize/3 when :skip_authorization_with is configured to be true" do
    setup %{application: application, resource_owner: resource_owner} do
      {
        :ok,
        %{
          application: application,
          config:
            Keyword.put(
              @config,
              :skip_authorization_with,
              fn _user, _application ->
                true
              end
            ),
          resource_owner: resource_owner
        }
      }
    end

    test "creates the grant and responds with native_redirect when url is native", context do
      %{
        application: application,
        config: config,
        resource_owner: resource_owner
      } = context

      assert {:native_redirect, %{code: code}} =
               Authorization.preauthorize(
                 resource_owner,
                 @valid_request,
                 config
               )

      access_grant =
        Repo.get_by(
          OauthAccessGrant,
          application_id: application.id,
          resource_owner_id: resource_owner.id,
          token: code
        )

      refute access_grant == nil
    end

    test "creates the grant andresponds with redirect when url is not native", context do
      %{
        application: application,
        config: config,
        resource_owner: resource_owner
      } = context

      application
      |> Changeset.change(redirect_uri: "https://foo.test/callback")
      |> Repo.update!()

      assert {:redirect, url} =
               Authorization.preauthorize(
                 resource_owner,
                 @valid_request,
                 config
               )

      access_grant =
        Repo.get_by(
          OauthAccessGrant,
          application_id: application.id,
          resource_owner_id: resource_owner.id
        )

      assert url =~ access_grant.token
    end

    test "pre-validation errors are passed through", context do
      %{config: config, resource_owner: resource_owner} = context

      assert {:error, @invalid_client, _status} =
               Authorization.preauthorize(
                 resource_owner,
                 Map.put(@valid_request, "client_id", "foo"),
                 config
               )
    end

    test "request validation errors are passed through", context do
      %{config: config, resource_owner: resource_owner} = context

      assert {:error, @invalid_redirect_uri, _status} =
               Authorization.preauthorize(
                 resource_owner,
                 Map.put(@valid_request, "redirect_uri", "foo"),
                 config
               )
    end
  end

  describe "#preauthorize/3 when PKCE is enabled" do
    test "validates the code challenge and returns the result", %{
      resource_owner: resource_owner,
      application: %{id: app_id} = application
    } do
      expected_scopes = Scopes.to_list(@valid_request["scope"])

      request =
        Map.merge(
          @valid_request,
          %{
            "code_challenge" => PKCE.generate_code_challenge(),
            "code_challenge_method" => "S256"
          }
        )

      assert {:ok, %{app: %OauthApplication{id: ^app_id}, scopes: ^expected_scopes}} =
               Authorization.preauthorize(
                 resource_owner,
                 request,
                 [{:use_pkce, true} | @config]
               )

      # Ensure that when the client supports PKCE it's being passed in correctly.
      %{pkce: :s256_only} =
        application
        |> Changeset.change(pkce: :s256_only)
        |> Repo.update!()

      assert {:ok, %{app: %OauthApplication{id: ^app_id}, scopes: ^expected_scopes}} =
               Authorization.preauthorize(
                 resource_owner,
                 request,
                 @config
               )
    end

    test "returns an error when there is something wrong w/ the challenge", %{
      resource_owner: resource_owner
    } do
      request =
        Map.merge(
          @valid_request,
          %{
            "code_challenge" => "invalid-format-challenge!",
            "code_challenge_method" => "S256"
          }
        )

      assert Authorization.preauthorize(
               resource_owner,
               request,
               [{:pkce, :all_methods} | @config]
             ) == {:error, @invalid_request, :bad_request}
    end
  end

  describe "#authorize/3" do
    test "returns rejects when no resource owner" do
      assert Authorization.authorize(nil, @valid_request, @config) ==
               {:error, @invalid_request, :bad_request}
    end

    test "returns error when invalid client", %{resource_owner: resource_owner} do
      request = Map.merge(@valid_request, %{"client_id" => "invalid"})

      assert Authorization.authorize(resource_owner, request, @config) ==
               {:error, @invalid_client, :unprocessable_entity}
    end

    test "returns error when no client_id", %{resource_owner: resource_owner} do
      request = Map.delete(@valid_request, "client_id")

      assert Authorization.authorize(resource_owner, request, @config) ==
               {:error, @invalid_request, :bad_request}
    end

    test "returns error when invalid scope", %{resource_owner: resource_owner} do
      request = Map.merge(@valid_request, %{"scope" => "app:read app:profile"})

      assert Authorization.authorize(resource_owner, request, @config) ==
               {:error, @invalid_scope, :unprocessable_entity}
    end

    test "returns error when invalid redirect uri", %{resource_owner: resource_owner} do
      request = Map.merge(@valid_request, %{"redirect_uri" => "/invalid/path"})

      assert Authorization.authorize(resource_owner, request, @config) ==
               {:error, @invalid_redirect_uri, :unprocessable_entity}
    end

    test "generates and returns the grant", %{resource_owner: resource_owner} do
      assert {:native_redirect, %{code: code}} =
               Authorization.authorize(resource_owner, @valid_request, @config)

      access_grant = Repo.get_by(OauthAccessGrant, token: code)

      assert access_grant.resource_owner_id == resource_owner.id

      assert access_grant.expires_in ==
               Config.authorization_code_expires_in(otp_app: :ex_oauth2_provider)

      assert access_grant.scopes == @valid_request["scope"]
    end

    test "generates grant with redirect uri", %{
      resource_owner: resource_owner,
      application: application
    } do
      QueryHelpers.change!(application,
        redirect_uri: "#{application.redirect_uri}\nhttps://example.com/path"
      )

      request =
        Map.merge(@valid_request, %{
          "redirect_uri" => "https://example.com/path?param=1",
          "state" => 40_612
        })

      assert {:redirect, redirect_uri} = Authorization.authorize(resource_owner, request, @config)

      access_grant = QueryHelpers.get_latest_inserted(OauthAccessGrant)

      # Param order is not guaranteed. So check everything safely.
      assert %URI{
               host: "example.com",
               path: "/path",
               query: query,
               scheme: "https"
             } = URI.parse(redirect_uri)

      assert URI.decode_query(query) == %{
               "code" => access_grant.token,
               "param" => "1",
               "state" => "40612"
             }
    end

    test "validates and stores PKCE data when enabled", %{resource_owner: resource_owner} do
      config = [{:pkce, :all_methods} | @config]
      challenge = PKCE.generate_code_challenge()

      request =
        Map.merge(
          @valid_request,
          %{
            "code_challenge" => challenge,
            "code_challenge_method" => "S256"
          }
        )

      assert {:native_redirect, %{code: code}} =
               Authorization.authorize(
                 resource_owner,
                 request,
                 config
               )

      access_grant = Repo.get_by(OauthAccessGrant, token: code)
      assert access_grant.code_challenge == challenge
      assert access_grant.code_challenge_method == :s256
    end

    test "returns error when PKCE validation fails", %{resource_owner: resource_owner} do
      request =
        Map.merge(
          @valid_request,
          %{
            "code_challenge" => "abc",
            "code_challenge_method" => "S256"
          }
        )

      assert {:error, %{error: :invalid_request}, :bad_request} =
               Authorization.authorize(
                 resource_owner,
                 request,
                 [{:pkce, :all_methods} | @config]
               )
    end
  end

  describe "#authorize/3 when application has no scope" do
    setup %{resource_owner: resource_owner, application: application} do
      application = QueryHelpers.change!(application, scopes: "")

      %{resource_owner: resource_owner, application: application}
    end

    test "error when invalid server scope", %{resource_owner: resource_owner} do
      request = Map.merge(@valid_request, %{"scope" => "public profile"})

      assert Authorization.authorize(resource_owner, request, @config) ==
               {:error, @invalid_scope, :unprocessable_entity}
    end

    test "generates grant", %{resource_owner: resource_owner} do
      request = Map.merge(@valid_request, %{"scope" => "public"})

      assert {:native_redirect, %{code: code}} =
               Authorization.authorize(resource_owner, request, @config)

      access_grant = Repo.get_by(OauthAccessGrant, token: code)
      assert access_grant.resource_owner_id == resource_owner.id
    end
  end

  describe "#deny/3" do
    test "returns access denied when the request is valid", %{resource_owner: resource_owner} do
      assert Authorization.deny(resource_owner, @valid_request, @config) ==
               {:error, @access_denied, :unauthorized}
    end

    test "returns error when no resource owner" do
      assert Authorization.deny(nil, @valid_request, @config) ==
               {:error, @invalid_request, :bad_request}
    end

    test "returns error when invalid client", %{resource_owner: resource_owner} do
      request = Map.merge(@valid_request, %{"client_id" => "invalid"})

      assert Authorization.deny(resource_owner, request, @config) ==
               {:error, @invalid_client, :unprocessable_entity}
    end

    test "returns error when no client_id", %{resource_owner: resource_owner} do
      request = Map.delete(@valid_request, "client_id")

      assert Authorization.deny(resource_owner, request, @config) ==
               {:error, @invalid_request, :bad_request}
    end

    test "returns a redirect when given a redirect URI", %{
      application: application,
      resource_owner: resource_owner
    } do
      QueryHelpers.change!(application,
        redirect_uri: "#{application.redirect_uri}\nhttps://example.com/path"
      )

      request =
        Map.merge(@valid_request, %{
          "redirect_uri" => "https://example.com/path?param=1",
          "state" => 40_612
        })

      {:redirect, uri} = assert Authorization.deny(resource_owner, request, @config)
      # Param order is not guaranteed. So check everything safely.
      assert %URI{
               host: "example.com",
               path: "/path",
               query: query,
               scheme: "https"
             } = URI.parse(uri)

      assert URI.decode_query(query) == %{
               "error" => "access_denied",
               "error_description" =>
                 "The resource owner or authorization server denied the request.",
               "param" => "1",
               "state" => "40612"
             }
    end
  end
end
