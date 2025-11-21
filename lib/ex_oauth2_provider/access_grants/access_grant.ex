defmodule ExOauth2Provider.AccessGrants.AccessGrant do
  @moduledoc """
  Handles the Ecto schema for access grant.

  ## Usage

  Configure `lib/my_project/oauth_access_grants/oauth_access_grant.ex` the following way:

      defmodule MyApp.OauthAccessGrants.OauthAccessGrant do
        use Ecto.Schema
        use ExOauth2Provider.AccessGrants.AccessGrant

        schema "oauth_access_grants" do
          access_grant_fields()

          timestamps()
        end
      end

  ## PKCE

  The PKCE columns are always `nil` regardless of whether or not the PKCE fields
  are present in the data unless you explicitly enable PKCE with the `with: :pkce`
  option.

  This allows one to enable PKCE for an app via config or explicitly on a
  request or endpoint basis.
  """

  alias ExOauth2Provider.Authorization.PKCE

  @type t :: Ecto.Schema.t()

  @doc false
  def attrs() do
    [
      {:code_challenge, :string},
      {:code_challenge_method, :string},
      {:expires_in, :integer, null: false},
      {:redirect_uri, :string, null: false},
      {:revoked_at, :utc_datetime},
      {:scopes, :string},
      {:token, :string, null: false}
    ]
  end

  @doc false
  def assocs() do
    [
      {:belongs_to, :resource_owner, :users},
      {:belongs_to, :application, :applications}
    ]
  end

  @doc false
  def indexes() do
    [
      {:token, true}
    ]
  end

  defmacro __using__(config) do
    quote do
      use ExOauth2Provider.Schema, unquote(config)

      import unquote(__MODULE__), only: [access_grant_fields: 0]
    end
  end

  defmacro access_grant_fields do
    quote do
      ExOauth2Provider.Schema.fields(unquote(__MODULE__))
    end
  end

  alias Ecto.Changeset
  alias ExOauth2Provider.{Mixin.Scopes, Utils}

  @spec changeset(Ecto.Schema.t(), map(), keyword()) :: Changeset.t()
  def changeset(grant, params, config) do
    castable = castable_attrs(config)
    required = required_attrs(config)

    grant
    |> Changeset.cast(params, castable)
    |> Changeset.assoc_constraint(:application)
    |> Changeset.assoc_constraint(:resource_owner)
    |> put_token()
    |> Scopes.put_scopes(grant.application.scopes, config)
    |> Scopes.validate_scopes(grant.application.scopes, config)
    |> Changeset.validate_required(required)
    |> Changeset.unique_constraint(:token)
  end

  @spec put_token(Ecto.Changeset.t()) :: Ecto.Changeset.t()
  def put_token(changeset) do
    Changeset.put_change(changeset, :token, Utils.generate_token())
  end

  defp castable_attrs(config) do
    castable = [
      :expires_in,
      :redirect_uri,
      :scopes
    ]

    if PKCE.required?(config) do
      [:code_challenge, :code_challenge_method] ++ castable
    else
      castable
    end
  end

  defp required_attrs(config) do
    castable = [
      :application,
      :expires_in,
      :redirect_uri,
      :resource_owner,
      :token
    ]

    if PKCE.required?(config) do
      [:code_challenge, :code_challenge_method] ++ castable
    else
      castable
    end
  end
end
