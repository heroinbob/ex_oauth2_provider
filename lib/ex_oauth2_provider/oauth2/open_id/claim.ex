defmodule ExOauth2Provider.OpenId.Claim do
  @type standard_claim :: :email | :email_verified

  @type t :: %__MODULE__{
          alias: atom(),
          includes: [t()],
          name: standard_claim()
        }

  defstruct [
    :alias,
    :name,
    includes: []
  ]

  def get_value_for(%__MODULE__{alias: alias, name: name}, source) when is_map(source) do
    field = alias || name
    Map.fetch!(source, field)
  end

  def new(%{name: _} = attrs) do
    includes =
      attrs
      |> Map.get(:includes, [])
      |> Enum.map(&new/1)

    attrs = Map.put(attrs, :includes, includes)

    struct(__MODULE__, attrs)
  end
end
