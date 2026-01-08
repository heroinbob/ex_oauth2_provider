defmodule ExOauth2Provider.Applications.ApplicationTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Applications.Application
  alias ExOauth2Provider.Applications.OpenIdSettings
  alias ExOauth2Provider.Test.Fixtures
  alias Dummy.OauthApplications.OauthApplication
  alias Dummy.Repo

  describe "changeset/2" do
    test "accepts valid attrs and has expected defaults" do
      user = Fixtures.build(:user)

      params = %{
        name: "Test App",
        owner: user,
        redirect_uri: "https://test.com"
      }

      assert {:ok, app} =
               %OauthApplication{}
               |> Application.changeset(params)
               |> Ecto.Changeset.apply_action(:validate)

      assert is_nil(app.open_id_settings)
      assert app.pkce == :disabled
      assert app.scopes == "public"
      assert app.secret =~ ~r/^[a-z0-9]+$/
      assert app.uid =~ ~r/^[a-z0-9]+$/
    end

    test "accepts a valid OpenIdSettings struct" do
      user = Fixtures.insert(:user)

      params = %{
        name: "Test App",
        open_id_settings: %{claims: ["email"], enforcement_policy: :always},
        owner: user,
        redirect_uri: "https://test.com"
      }

      assert %OauthApplication{
               open_id_settings: %OpenIdSettings{
                 claims: ["email"],
                 enforcement_policy: :always
               }
             } =
               %OauthApplication{}
               |> Application.changeset(params)
               |> Repo.insert!()
    end
  end

  describe "changeset/2 with existing application" do
    setup do
      application = Ecto.put_meta(%OauthApplication{}, state: :loaded)

      {:ok, application: application}
    end

    test "validates name", %{application: application} do
      changeset = Application.changeset(application, %{name: ""})
      assert changeset.errors[:name]
    end

    test "validates uid", %{application: application} do
      changeset = Application.changeset(application, %{uid: ""})
      assert changeset.errors[:uid]
    end

    test "validates secret", %{application: application} do
      changeset = Application.changeset(application, %{secret: nil})
      assert changeset.errors[:secret] == {"can't be blank", []}

      changeset = Application.changeset(application, %{secret: ""})
      assert is_nil(changeset.errors[:secret])
    end

    test "requires valid redirect uri", %{application: application} do
      changeset = Application.changeset(application, %{redirect_uri: ""})
      assert changeset.errors[:redirect_uri]
    end

    test "require valid redirect uri", %{application: application} do
      ["", "invalid", "https://example.com invalid", "https://example.com http://example.com"]
      |> Enum.each(fn redirect_uri ->
        changeset = Application.changeset(application, %{redirect_uri: redirect_uri})
        assert changeset.errors[:redirect_uri]
      end)
    end

    test "requires PKCE to be one of the supported values", %{application: application} do
      # Default should be :disabled by default.
      changeset = Application.changeset(application, %{})
      refute Keyword.has_key?(changeset.errors, :pkce)
      assert changeset.data.pkce == :disabled

      changeset = Application.changeset(application, %{pkce: ""})
      refute Keyword.has_key?(changeset.errors, :pkce)
      assert changeset.data.pkce == :disabled

      changeset = Application.changeset(application, %{pkce: nil})
      assert {"can't be blank", _} = changeset.errors[:pkce]

      changeset = Application.changeset(application, %{pkce: :yes_please})
      assert {"is invalid", _} = changeset.errors[:pkce]

      # Disabled won't trigger a change so this tests that the non disabled
      # work as expected
      for value <- [:all_methods, :plain_only, :s256_only] do
        changeset = Application.changeset(application, %{pkce: value})
        refute Keyword.has_key?(changeset.errors, :pkce)
        assert changeset.changes.pkce == value
      end

      changeset = Application.changeset(application, %{pkce: :disabled})
      refute Keyword.has_key?(changeset.errors, :pkce)
      refute Map.has_key?(changeset.changes, :pkce)
      assert changeset.data.pkce == :disabled
    end

    test "doesn't require scopes", %{application: application} do
      changeset = Application.changeset(application, %{scopes: ""})
      refute changeset.errors[:scopes]
    end

    test "allows is_trusted to be changed" do
      app =
        Fixtures.application()
        |> Application.changeset(%{is_trusted: true})
        |> Repo.update!()

      assert app.is_trusted == true
    end

    test "changes the open ID settings" do
      app =
        Fixtures.insert(
          :application,
          open_id_settings: %{enforcement_policy: :always}
        )

      assert {
               :ok,
               %OauthApplication{
                 open_id_settings: %OpenIdSettings{
                   enforcement_policy: :when_in_scope
                 }
               }
             } =
               app
               |> Application.changeset(%{
                 open_id_settings: %{enforcement_policy: :when_in_scope}
               })
               |> Ecto.Changeset.apply_action(:validate)

      assert {
               :ok,
               %OauthApplication{open_id_settings: nil}
             } =
               app
               |> Application.changeset(%{open_id_settings: nil})
               |> Ecto.Changeset.apply_action(:validate)
    end
  end

  defmodule OverrideOwner do
    @moduledoc false

    use Ecto.Schema
    use ExOauth2Provider.Applications.Application, otp_app: :ex_oauth2_provider

    if System.get_env("UUID") do
      @primary_key {:id, :binary_id, autogenerate: true}
      @foreign_key_type :binary_id
    end

    schema "oauth_applications" do
      belongs_to(:owner, __MODULE__)

      application_fields()
      timestamps()
    end
  end

  test "with overridden `:owner`" do
    assert %Ecto.Association.BelongsTo{owner: OverrideOwner} =
             OverrideOwner.__schema__(:association, :owner)
  end
end
