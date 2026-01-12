defmodule ExOauth2Provider.OpenIdTest do
  use ExOauth2Provider.TestCase, async: true

  alias ExOauth2Provider.OpenId
  alias ExOauth2Provider.Test.Fixtures

  describe "enabled?1" do
    test "returns true when the openid settings have enforcement of :always" do
      application =
        Fixtures.build(
          :application,
          open_id_settings: Fixtures.build(:open_id_settings, enforcement_policy: :always)
        )

      context = Fixtures.authorization_request_context(client: application)

      assert OpenId.enabled?(context) == true
    end

    test "returns true when the openid settings have enforcement of :when_in_scope" do
      application =
        Fixtures.build(
          :application,
          open_id_settings: Fixtures.build(:open_id_settings, enforcement_policy: :when_in_scope)
        )

      context = Fixtures.authorization_request_context(client: application)

      assert OpenId.enabled?(context) == true
    end

    test "returns false when the openid settings have enforcement of :disabled" do
      application =
        Fixtures.build(
          :application,
          open_id_settings: Fixtures.build(:open_id_settings, enforcement_policy: :disabled)
        )

      context = Fixtures.authorization_request_context(client: application)

      assert OpenId.enabled?(context) == false
    end

    test "returns false when there are no openid settings" do
      application = Fixtures.build(:application, open_id_settings: nil)
      context = Fixtures.authorization_request_context(client: application)

      assert OpenId.enabled?(context) == false
    end
  end

  describe "valid?/1 when enforcement_policy is :always" do
    test "returns true when openid is in scope" do
      application =
        Fixtures.insert(
          :application,
          open_id_settings: Fixtures.build(:open_id_settings, enforcement_policy: :always),
          scopes: "public openid read write"
        )

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => application.redirect_uri,
            "scope" => "openid"
          }
        )

      assert OpenId.valid?(context) == true
    end

    test "returns false when openid is not in scope" do
      application =
        Fixtures.insert(
          :application,
          open_id_settings: Fixtures.build(:open_id_settings, enforcement_policy: :always),
          scopes: "public openid read write"
        )

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => application.redirect_uri,
            "scope" => "public"
          }
        )

      assert OpenId.valid?(context) == false
    end
  end

  describe "valid?/1 when enforcement_policy is :when_in_scope" do
    test "returns true when openid is in scope" do
      application =
        Fixtures.insert(
          :application,
          open_id_settings: Fixtures.build(:open_id_settings, enforcement_policy: :when_in_scope),
          scopes: "public openid read write"
        )

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => application.redirect_uri,
            "scope" => "openid"
          }
        )

      assert OpenId.valid?(context) == true
    end

    test "returns true when openid is not in scope" do
      application =
        Fixtures.insert(
          :application,
          open_id_settings: Fixtures.build(:open_id_settings, enforcement_policy: :when_in_scope),
          scopes: "public openid read write"
        )

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => application.redirect_uri,
            "scope" => "public"
          }
        )

      assert OpenId.valid?(context) == true
    end
  end

  describe "valid?/1 when enforcement_policy is :disabled" do
    test "returns true when openid is not in scope" do
      application =
        Fixtures.insert(
          :application,
          open_id_settings: Fixtures.build(:open_id_settings, enforcement_policy: :disabled),
          scopes: "public openid read write"
        )

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => application.redirect_uri,
            "scope" => "public"
          }
        )

      assert OpenId.valid?(context) == true
    end

    test "returns false when openid is in scope" do
      application =
        Fixtures.insert(
          :application,
          open_id_settings: Fixtures.build(:open_id_settings, enforcement_policy: :disabled),
          scopes: "public openid read write"
        )

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => application.redirect_uri,
            "scope" => "openid"
          }
        )

      assert OpenId.valid?(context) == true
    end
  end

  describe "valid?/1 when enforcement_policy is not defined" do
    test "returns true when openid is not in scope" do
      application =
        Fixtures.insert(
          :application,
          open_id_settings: nil,
          scopes: "public openid read write"
        )

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => application.redirect_uri,
            "scope" => "public"
          }
        )

      assert OpenId.valid?(context) == true
    end

    test "returns false when openid is in scope" do
      application =
        Fixtures.insert(
          :application,
          open_id_settings: nil,
          scopes: "public openid read write"
        )

      context =
        Fixtures.authorization_request_context(
          client: application,
          request: %{
            "redirect_uri" => application.redirect_uri,
            "scope" => "openid"
          }
        )

      assert OpenId.valid?(context) == false
    end
  end
end
