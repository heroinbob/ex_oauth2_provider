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

  @doc """
  Return the value from the given source that is represented by the given claim.
  The source MUST have the specified value or an error will be raised.
  """
  @spec get_value_for!(t(), source :: map()) :: t()
  def get_value_for!(%__MODULE__{alias: alias, name: name}, source) when is_map(source) do
    field = alias || name
    Map.fetch!(source, field)
  end

  @spec new(attrs :: map()) :: t()
  def new(%{name: _} = attrs) do
    includes =
      attrs
      |> Map.get(:includes, [])
      |> Enum.map(&new/1)

    attrs = Map.put(attrs, :includes, includes)

    struct(__MODULE__, attrs)
  end
end
