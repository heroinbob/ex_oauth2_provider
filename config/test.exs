Application.ensure_loaded(:ex_oauth2_provider)

import Config

config :ex_oauth2_provider, namespace: Dummy

config :ex_oauth2_provider, ExOauth2Provider,
  application: Dummy.OauthApplications.OauthApplication,
  access_token: Dummy.OauthAccessTokens.OauthAccessToken,
  default_scopes: ~w(public),
  device_flow_verification_uri: "https://test.site.net/device",
  grant_flows: ~w(
    authorization_code
    client_credentials
    device_code
  ),
  open_id: %{
    id_token_issuer: "test-iss",
    # Can't use fixtures here so have to load it manually. Generated via the following command
    # ssh-keygen -t rsa -b 4096 -m PEM -E SHA256 -f test/support/open_id/rsa256_key.pem
    #
    # There is no passphrase.
    id_token_signing_key_pem: File.read!("test/support/open_id/rsa256_key.pem"),
    id_token_signing_key_algorithm: "RS256",
    id_token_signing_key_id: "test-key-20260121-142820"
  },
  optional_scopes: ~w(read write),
  password_auth: {Dummy.Auth, :auth},
  repo: Dummy.Repo,
  resource_owner: Dummy.Users.User,
  revoke_refresh_token_on_use: true,
  use_refresh_token: true

config :ex_oauth2_provider, Dummy.Repo,
  database: "ex_oauth2_provider_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  priv: "test/support/priv",
  username: "postgres",
  password: "postgres"
