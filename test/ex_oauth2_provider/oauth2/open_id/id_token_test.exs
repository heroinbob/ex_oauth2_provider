defmodule ExOauth2Provider.OpenId.IdTokenTest do
  # Do not run tests async when doing config testing
  use ExOauth2Provider.TestCase, async: false
  use ExOauth2Provider.Test.ConfigChanges

  alias ExOauth2Provider.OpenId.IdToken
  alias ExOauth2Provider.Test.Fixtures

  describe "new/3" do
    test "returns an ID token" do
      token = Fixtures.insert(:access_token)
      aud = "id-token-aud"
      iss = "id-token-iss"

      # The timestamps in this test are NaiveDateTime per the schema and DB table
      assert %NaiveDateTime{} = token.inserted_at

      request_context = Fixtures.token_request_context()

      # Set the lifespan to a known value for the test.
      add_open_id_changes(%{
        id_token_audience: aud,
        id_token_issuer: iss,
        id_token_lifespan: 100
      })

      assert %{
               aud: ^aud,
               auth_time: auth_time,
               exp: expires_at,
               iat: issued_at,
               iss: ^iss,
               sub: user_id
             } = IdToken.new(token, request_context, [])

      now = DateTime.to_unix(DateTime.utc_now())

      # To keep this from being flaky make sure that the time is within a few
      # seconds of now.
      assert auth_time in now..(now + 3)

      # Expiration is the token expiration plus the configured lifespan.
      # Default is one week so we can do a basic assertion on it.
      assert expires_at == auth_time + 100

      assert issued_at == auth_time
      assert user_id == token.resource_owner.id
    end

    test "supports DateTime timestamps" do
      # Our test schemas and DB yield naive datetime structs. Others may
      # use unix timestamps which yield DateTime structs.
      token =
        :access_token
        |> Fixtures.insert(expires_in: 100)
        |> Map.put(:inserted_at, DateTime.utc_now())

      request_context = Fixtures.token_request_context()

      add_open_id_changes(%{
        id_token_audience: "id-token-aud",
        id_token_issuer: "id-token-iss",
        id_token_lifespan: 100
      })

      assert %{
               auth_time: auth_time,
               exp: expires_at,
               iat: issued_at
             } = IdToken.new(token, request_context, [])

      now = DateTime.to_unix(token.inserted_at)

      # To keep this from being flaky make sure that the time is within a few
      # seconds of now.
      assert auth_time in now..(now + 3)
      assert expires_at == auth_time + 100
      assert issued_at == auth_time
    end

    test "adds additional claims when in scope and configured" do
      token = Fixtures.insert(:access_token, scopes: "openid write read email")
      request_context = Fixtures.token_request_context()

      add_open_id_changes(%{
        claims: [%{name: :email}],
        id_token_audience: "id-token-aud",
        id_token_issuer: "id-token-iss"
      })

      assert %{
               aud: _,
               auth_time: _,
               email: email,
               exp: _,
               iat: _,
               iss: _,
               sub: _
             } = IdToken.new(token, request_context, [])

      assert email == token.resource_owner.email
    end

    test "adds nested claims when configured" do
      token = Fixtures.insert(:access_token, scopes: "openid write read email")
      request_context = Fixtures.token_request_context()

      # This is a test hack. Let's pass in a map with what we need just to verify.
      user = token.resource_owner |> Map.from_struct() |> Map.put(:email_verified, true)
      token = %{token | resource_owner: user}

      add_open_id_changes(%{
        claims: [
          %{
            name: :email,
            includes: [%{name: :email_verified}]
          }
        ],
        id_token_audience: "id-token-aud",
        id_token_issuer: "id-token-iss"
      })

      assert %{
               aud: _,
               auth_time: _,
               email: email,
               email_verified: email_verified,
               exp: _,
               iat: _,
               iss: _,
               sub: _
             } = IdToken.new(token, request_context, [])

      assert email == user.email
      assert email_verified == true
    end

    test "works with claims that are named differently in the user schema" do
      token = Fixtures.insert(:access_token, scopes: "openid write read email")
      request_context = Fixtures.token_request_context()

      # This is a test hack. Let's pass in a map with what we need just to verify.
      user =
        token.resource_owner
        |> Map.from_struct()
        |> Map.merge(%{is_verified: true, private_email: "test@success.com"})

      token = %{token | resource_owner: user}

      add_open_id_changes(%{
        claims: [
          %{
            alias: :private_email,
            name: :email,
            includes: [%{alias: :is_verified, name: :email_verified}]
          }
        ],
        id_token_audience: "id-token-aud",
        id_token_issuer: "id-token-iss"
      })

      assert %{
               aud: _,
               auth_time: _,
               email: email,
               email_verified: email_verified,
               exp: _,
               iat: _,
               iss: _,
               sub: _
             } = IdToken.new(token, request_context, [])

      assert email == user.private_email
      assert email_verified == true
    end

    test "ignores requested claims when present but not configured" do
      token = Fixtures.insert(:access_token, scopes: "openid write read email")
      request_context = Fixtures.token_request_context()

      assert id_token = IdToken.new(token, request_context, [])

      refute Map.has_key?(id_token, :email)
      refute Map.has_key?(id_token, :email_verified)
    end

    test "ignores configured claims that are not requested" do
      token = Fixtures.insert(:access_token, scopes: "openid write read")
      request_context = Fixtures.token_request_context()

      add_open_id_changes(%{
        claims: [%{name: :email}],
        id_token_audience: "id-token-aud",
        id_token_issuer: "id-token-iss"
      })

      assert id_token = IdToken.new(token, request_context, [])

      refute Map.has_key?(id_token, :email)
      refute Map.has_key?(id_token, :email_verified)
    end

    test "adds nonce when present" do
      grant = Fixtures.insert(:access_grant, open_id_nonce: "heynow")
      token = Fixtures.insert(:access_token)
      request_context = Fixtures.token_request_context(access_grant: grant)

      assert %{nonce: "heynow"} = IdToken.new(token, request_context, [])
    end

    test "supports overriding the app config" do
      token = Fixtures.insert(:access_token)
      aud = "override-aud"
      iss = "override-iss"
      lifespan = 42

      request_context = Fixtures.token_request_context()

      # Set the lifespan to a known value for the test.
      config =
        :ex_oauth2_provider
        |> Application.get_env(ExOauth2Provider)
        |> Keyword.fetch!(:open_id)
        |> Map.merge(%{
          id_token_audience: aud,
          id_token_issuer: iss,
          id_token_lifespan: lifespan
        })

      assert %{
               aud: ^aud,
               auth_time: auth_time,
               exp: expires_at,
               iat: issued_at,
               iss: ^iss
             } = IdToken.new(token, request_context, open_id: config)

      now = DateTime.to_unix(DateTime.utc_now())

      # To keep this from being flaky make sure that the time is within a few
      # seconds of now.
      assert auth_time in now..(now + 3)

      # Expiration is the token expiration plus the configured lifespan.
      # Default is one week so we can do a basic assertion on it.
      assert expires_at == auth_time + lifespan

      assert issued_at == auth_time
    end
  end
end
