defmodule ExOauth2Provider.OpenId.OpenIdSettings do
  use Ecto.Schema

  alias Ecto.Changeset

  @enforcement_policies [
    :always,
    :disabled,
    :when_in_scope
  ]

  @type enforcement_policy ::
          unquote(
            @enforcement_policies
            |> Enum.reverse()
            |> Enum.reduce(&quote(do: unquote(&1) | unquote(&2)))
          )

  @primary_key false
  embedded_schema do
    field(:claims, {:array, :string}, default: [])

    field(
      :enforcement_policy,
      Ecto.Enum,
      default: :disabled,
      values: @enforcement_policies
    )
  end

  def changeset(settings, attrs) do
    Changeset.cast(settings, attrs, [:claims, :enforcement_policy])
  end

  @doc """
  Returns a list of the supported OpenID enforcement options.
  """
  @spec enforcement_policies() :: enforcement_policy()
  def enforcement_policies, do: @enforcement_policies
end
