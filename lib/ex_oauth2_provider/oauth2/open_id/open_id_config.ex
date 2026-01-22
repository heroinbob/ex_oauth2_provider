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

  ## Configuration

  The following is a synopsis of configuration keys and their usage.

  ### Required Keys

  * `:id_token_audience`              - The value to put for the `aud` claim in
                                        the ID token.

  * `:id_token_issuer`                - The value to put for the `iss` claim in
                                        the ID token.

  * `:id_token_signing_key_algorithm` - The algorithm to use when signing.
                                        The key represented by the pem
                                        should rely on this algorithm.

  * `:id_token_signing_key_pem`       - The private key pem content. This
                                        will be converted to a JOSE.JWK.

  ### Optional Keys
  * `:claims`                  - A map of claims that should be included.

  * `:id_token_lifespan`       - The number of seconds that the ID token is
                                 valid for. Default is one week.

  * `:id_token_signing_key_id` - When defined the kid attribute will be
                                 added to the JWS header.

  ## TODO

  * Add a global enforcement policy to control it's use globally.
  * Add additional claims features as needed.
  """
  alias ExOauth2Provider.Config
  alias ExOauth2Provider.OpenId.Claim

  @type t :: %__MODULE__{
          claims: [Claim.t()],
          id_token_audience: String.t(),
          id_token_issuer: String.t(),
          id_token_lifespan: non_neg_integer(),
          id_token_signing_key: JOSE.JWK.t(),
          id_token_signing_key_algorithm: String.t(),
          id_token_signing_key_id: String.t() | nil
        }

  @one_week 60 * 60 * 24 * 7

  defstruct [
    :id_token_audience,
    :id_token_issuer,
    :id_token_signing_key,
    :id_token_signing_key_algorithm,
    :id_token_signing_key_id,
    claims: [],
    id_token_lifespan: @one_week
  ]

  @doc """
  Return the current config. You can pass in overrides optionally.
  """
  @spec get() :: t()
  @spec get(overrides :: keyword()) :: t()
  def get(overrides \\ []) do
    config =
      overrides
      |> Config.open_id_config()
      |> Map.reject(fn {_k, v} -> is_nil(v) end)

    signing_key =
      config
      |> Map.fetch!(:id_token_signing_key_pem)
      |> JOSE.JWK.from_pem()

    %__MODULE__{
      claims: config |> Map.get(:claims, []) |> Enum.map(&Claim.new/1),
      id_token_audience: Map.fetch!(config, :id_token_audience),
      id_token_issuer: Map.fetch!(config, :id_token_issuer),
      id_token_lifespan: Map.get(config, :id_token_lifespan, @one_week),
      id_token_signing_key: signing_key,
      id_token_signing_key_algorithm: Map.fetch!(config, :id_token_signing_key_algorithm),
      id_token_signing_key_id: Map.get(config, :id_token_signing_key_id)
    }
  end
end
