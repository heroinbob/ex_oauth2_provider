defmodule ExOauth2Provider.Token.AuthorizationCode.RequestParamsTest do
  use ExUnit.Case, async: true

  alias Dummy.OauthAccessGrants.OauthAccessGrant
  alias ExOauth2Provider.Token.AuthorizationCode.RequestParams
  alias ExOauth2Provider.Test.PKCE

  describe "valid?/2" do
    test "returns true for valid params" do
      assert RequestParams.valid?(
               %{
                 access_grant: %OauthAccessGrant{redirect_uri: "test"},
                 request: %{"redirect_uri" => "test"}
               },
               []
             ) == true
    end

    test "returns true for valid params with PKCE" do
      verifier = PKCE.generate_code_verifier()
      challenge = PKCE.generate_code_challenge(verifier, :s256)

      assert RequestParams.valid?(
               %{
                 access_grant: %OauthAccessGrant{
                   code_challenge: challenge,
                   code_challenge_method: :s256,
                   redirect_uri: "test"
                 },
                 request: %{
                   "code_verifier" => verifier,
                   "redirect_uri" => "test"
                 }
               },
               pkce: :enabled
             ) == true
    end

    test "returns false when redirect URI is invalid" do
      assert RequestParams.valid?(
               %{
                 access_grant: %OauthAccessGrant{redirect_uri: "test"},
                 request: %{"redirect_uri" => "different-one"}
               },
               []
             ) == false
    end

    test "returns false when PKCE is invalid" do
      verifier = PKCE.generate_code_verifier()

      assert RequestParams.valid?(
               %{
                 access_grant: %OauthAccessGrant{
                   code_challenge: "challenge",
                   code_challenge_method: "S256",
                   redirect_uri: "test"
                 },
                 request: %{
                   "code_verifier" => verifier,
                   "redirect_uri" => "test"
                 }
               },
               pkce: :enabled
             ) == false
    end

    test "returns false when the context is unexpected" do
      assert RequestParams.valid?(%{}, []) == false
      assert RequestParams.valid?(%{access_grant: "grant"}, []) == false
      assert RequestParams.valid?(%{request: "request"}, []) == false
    end
  end
end
