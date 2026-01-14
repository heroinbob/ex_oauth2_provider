defmodule ExOauth2Provider.OpenId.IdTokenTest do
  use ExOauth2Provider.TestCase, async: true

  alias ExOauth2Provider.OpenId.IdToken
  alias ExOauth2Provider.Test.Fixtures

  describe "new/3" do
    test "returns an ID token" do
      token =
        Fixtures.insert(
          :access_token,
          expires_in: 100
        )

      # The timestamps in this test are NaiveDateTime per the schema and DB table
      assert %NaiveDateTime{} = token.inserted_at

      request_context = Fixtures.token_request_context()

      assert %{
               aud: "https://veeps.com",
               auth_time: auth_time,
               exp: expires_at,
               iat: issued_at,
               iss: "https://veeps.com",
               sub: user_id
             } = IdToken.new(token, request_context, [])

      now = DateTime.to_unix(DateTime.utc_now())

      # To keep this from being flaky make sure that the time is within a few
      # seconds of now.
      assert auth_time in now..(now + 3)
      assert expires_at == auth_time + token.expires_in
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

      assert %{
               auth_time: auth_time,
               exp: expires_at,
               iat: issued_at
             } = IdToken.new(token, request_context, [])

      now = DateTime.to_unix(token.inserted_at)

      # To keep this from being flaky make sure that the time is within a few
      # seconds of now.
      assert auth_time in now..(now + 3)
      assert expires_at == auth_time + token.expires_in
      assert issued_at == auth_time
    end

    test "adds additional claims when in scope and configured" do
      token = Fixtures.insert(:access_token, scopes: "openid write read email")
      request_context = Fixtures.token_request_context()
      config = [open_id: %{claims: [%{name: :email}]}]

      assert %{
               aud: _,
               auth_time: _,
               email: email,
               exp: _,
               iat: _,
               iss: _,
               sub: _
             } = IdToken.new(token, request_context, config)

      assert email == token.resource_owner.email
    end

    test "adds nested claims when configured" do
      token = Fixtures.insert(:access_token, scopes: "openid write read email")
      request_context = Fixtures.token_request_context()

      # This is a test hack. Let's pass in a map with what we need just to verify.
      user = token.resource_owner |> Map.from_struct() |> Map.put(:email_verified, true)
      token = %{token | resource_owner: user}

      config = [
        open_id: %{
          claims: [
            %{
              name: :email,
              includes: [%{name: :email_verified}]
            }
          ]
        }
      ]

      assert %{
               aud: _,
               auth_time: _,
               email: email,
               email_verified: email_verified,
               exp: _,
               iat: _,
               iss: _,
               sub: _
             } = IdToken.new(token, request_context, config)

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

      config = [
        open_id: %{
          claims: [
            %{
              alias: :private_email,
              name: :email,
              includes: [%{alias: :is_verified, name: :email_verified}]
            }
          ]
        }
      ]

      assert %{
               aud: _,
               auth_time: _,
               email: email,
               email_verified: email_verified,
               exp: _,
               iat: _,
               iss: _,
               sub: _
             } = IdToken.new(token, request_context, config)

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
      config = [open_id: %{claims: [%{name: :email}]}]

      assert id_token = IdToken.new(token, request_context, config)

      refute Map.has_key?(id_token, :email)
      refute Map.has_key?(id_token, :email_verified)
    end

    test "adds nonce when present" do
      raise "TODO"
    end
  end
end
