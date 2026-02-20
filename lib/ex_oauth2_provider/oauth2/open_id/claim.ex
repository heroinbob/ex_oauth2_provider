defmodule ExOauth2Provider.OpenId.Claim do
  @type standard_claim :: :email | :email_verified

  @type t :: %__MODULE__{
          alias: atom(),
          includes: [t()],
          name: standard_claim(),
          transformer: function() | nil,
          value_when_missing: any()
        }

  defstruct [
    :alias,
    :name,
    :transformer,
    :value_when_missing,
    includes: []
  ]

  @doc """
  Return the value from the given source that is represented by the given claim.

  ## Options

  * `:alias` - When you want to return a value from the source that's named differently
               than the claim you can specify it's name (alias). For example perhaps
               the source has more than one email and you want to return `work_email`
               as the value for `email`. Alias is ignored when `:transformer` is given.

  * `:transformer` - When passed a function it is executed with the given `source`
                     and the result of the function is used as the value for the claim.
                     You can specify a transformer when you wish to mutate a value into
                     something else or use a derived value.

  * `:value_when_missing` - Default is `nil`. You can specify a value  to use when the
                            `source` does not have the specified attribute. This value
                            is ignored if you specify `:transformer`.
  """
  @spec get_value_for(t(), source :: map()) :: t()
  def get_value_for(%__MODULE__{transformer: transformer}, source)
      when is_map(source) and is_function(transformer) do
    transformer.(source)
  end

  def get_value_for(
        %__MODULE__{
          alias: alias,
          name: name,
          value_when_missing: default
        },
        source
      )
      when is_map(source) do
    field = alias || name
    Map.get(source, field, default)
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
