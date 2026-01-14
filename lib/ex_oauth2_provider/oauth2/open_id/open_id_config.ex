defmodule ExOauth2Provider.OpenId.OpenIdConfig do
  @moduledoc """
  Configuration for OpenID.

  At present this is very, very basic and supports defining
  which claims you'd like to support aside from the ones
  required in the OpenID Connect definition.

  To define a claim you just need to provide a map with the
  name of the field and optionally the alias which is the
  name of the field in the user struct.

  ## Examples

  Here is the most basic setup.

    open_id: %{
      claims: [
        %{name: :email},
      ]
    }

  You can also tell it to use a different field for the claim.

    open_id: %{
      claims: [
        %{name: :email, alias: :personal_email},
      ]
    }

  Including additional claims when one is requested is supported too.

    open_id: %{
      claims: [
        %{
          name: :email,
          including: [
            %{name: :email_verified}
          ]
        }
      ]
    }

  ## TODO

  * Add a global enforcement policy to control it's use globally.
  * Add additional claims features as needed.
  """
  alias ExOauth2Provider.Config
  alias ExOauth2Provider.OpenId.Claim

  @type t :: %__MODULE__{
          claims: [Claim.t()]
        }

  defstruct claims: []

  @doc """
  Return the current config. You can pass in overrides optionally.
  """
  @spec get() :: t()
  @spec get(overrides :: keyword()) :: t()
  def get(overrides \\ []) do
    overrides
    |> Config.open_id_config()
    |> new()
  end

  defp new(attrs) do
    claims =
      attrs
      |> Map.get(:claims, [])
      |> Enum.map(&Claim.new/1)

    %__MODULE__{claims: claims}
  end
end
