defmodule ExOauth2Provider.Mixin.Revocable do
  @moduledoc false
  import Ecto.Query

  alias Ecto.{Changeset, Schema}
  alias ExOauth2Provider.Config
  alias ExOauth2Provider.Schema, as: SchemaHelpers

  defdelegate repo(config), to: Config

  @doc """
  Revoke data.

  ## Examples

      iex> revoke(data)
      {:ok, %Data{revoked_at: ~N[2017-04-04 19:21:22.292762], ...}}

      iex> revoke(invalid_data)
      {:error, %Ecto.Changeset{}}
  """
  @spec revoke(Schema.t(), keyword()) :: {:ok, Schema.t()} | {:error, Changeset.t()}
  def revoke(data, config \\ []) do
    data
    |> revoke_query()
    |> case do
      nil -> {:ok, data}
      query -> repo(config).update(query)
    end
  end

  @doc """
  Same as `revoke/1` but raises error.
  """
  @spec revoke!(Schema.t(), keyword()) :: Schema.t() | no_return
  def revoke!(data, config \\ []) do
    data
    |> revoke_query()
    |> case do
      nil -> data
      query -> repo(config).update!(query)
    end
  end

  @doc """
  Revoke all access tokens belonging to the resource owner for the specified app.
  All previously revoked tokens are ignored. This effectively ends all active access
  and requires re-authentication after calling.
  """
  @spec revoke_by_app_and_resource_owner(
          app_id :: String.t() | non_neg_integer(),
          resource_owner_id :: String.t() | non_neg_integer(),
          opts :: map()
        ) :: non_neg_integer()
  def revoke_by_app_and_resource_owner(app_id, resource_owner_id, opts) do
    %{repo: repo, schema: schema} = opts
    revoked_at = SchemaHelpers.__timestamp_for__(schema, :revoked_at)

    query =
      schema
      |> where([s], s.application_id == ^app_id)
      |> where([s], s.resource_owner_id == ^resource_owner_id)
      |> where([s], is_nil(s.revoked_at))

    query
    |> repo.update_all(set: [revoked_at: revoked_at])
    |> elem(0)
  end

  defp revoke_query(%struct{revoked_at: nil} = data) do
    Changeset.change(data, revoked_at: SchemaHelpers.__timestamp_for__(struct, :revoked_at))
  end

  defp revoke_query(_data), do: nil

  @doc """
  Filter revoked data.

  ## Examples

      iex> filter_revoked(%Data{revoked_at: nil, ...}}
      %Data{}

      iex> filter_revoked(%Data{revoked_at: ~N[2017-04-04 19:21:22.292762], ...}}
      nil
  """
  @spec filter_revoked(Schema.t()) :: Schema.t() | nil
  def filter_revoked(data) do
    case is_revoked?(data) do
      true -> nil
      false -> data
    end
  end

  @doc """
  Checks if data has been revoked.

  ## Examples

      iex> is_revoked?(%Data{revoked_at: nil, ...}}
      false

      iex> is_revoked?(%Data{revoked_at: ~N[2017-04-04 19:21:22.292762], ...}}
      true
  """
  @spec is_revoked?(Schema.t()) :: boolean()
  def is_revoked?(%{revoked_at: nil}), do: false
  def is_revoked?(_), do: true
end
