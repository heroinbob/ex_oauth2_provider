defmodule ExOauth2Provider.Applications.OpenIdSettings do
  use Ecto.Schema

  alias Ecto.Changeset
  alias ExOauth2Provider.OpenId

  @enforcement_policies OpenId.enforcement_policies()

  @primary_key false
  embedded_schema do
    field(:claims, {:array, :string}, default: [])

    field(
      :enforcement_policy,
      Ecto.Enum,
      default: :never,
      values: @enforcement_policies
    )
  end

  def changeset(settings, attrs) do
    Changeset.cast(settings, attrs, [:claims, :enforcement_policy])
  end
end
