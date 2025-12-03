defmodule Mix.Tasks.ExOauth2Provider.AddPkceFields do
  @shortdoc "Generates migration for adding PKCE fields"

  @moduledoc """
  Generates a migration file that adds the PKCE columns to AccessGrants.

      # Update the default table which is `oauth_access_grants`
      mix ex_oauth2_provider.add_pkce_fields -r MyApp.Repo

      # Update your custom table name
      mix ex_oauth2_provider.add_pkce_fields -r MyApp.Repo --table some_other_name

  This generator will add the oauth2 migration file in `priv/repo/migrations`.

  The repository must be set under `:ecto_repos` in the current app
  configuration or given via the `-r` option.

  By default, the migration will be generated to the
  "priv/YOUR_REPO/migrations" directory of the current application but it
  can be configured to be any subdirectory of `priv` by specifying the
  `:priv` key under the repository configuration.

  ## Arguments

    * `-r`, `--repo` - the repo module
    * `--table` - The name of the table to modify
  """
  use Mix.Task

  alias Mix.{Ecto, ExOauth2Provider, ExOauth2Provider.Migration}

  @switches [table: :string]
  @default_opts [table: "oauth_access_grants"]
  @mix_task "ex_oauth2_provider.add_pkce_fields"

  @template """
  defmodule <%= inspect migration.repo %>.Migrations.AddOauthPkceFields do
    use Ecto.Migration

    def change do
      alter table(:<%= migration.table %>) do
        add :code_challenge, :string
        add :code_challenge_method, :string
      end
    end
  end
  """

  @impl true
  def run(args) do
    ExOauth2Provider.no_umbrella!(@mix_task)

    args
    |> ExOauth2Provider.parse_options(@switches, @default_opts)
    |> parse()
    |> create_file(args)
  end

  defp parse({config, _parsed, _invalid}), do: config

  defp create_file(config, args) do
    args
    |> Ecto.parse_repo()
    |> Enum.map(&ensure_repo(&1, args))
    |> Enum.map(&Map.put(config, :repo, &1))
    |> Enum.each(&create_file/1)
  end

  defp create_file(%{repo: repo, table: table}) do
    content =
      EEx.eval_string(
        @template,
        migration: %{
          repo: repo,
          table: table
        }
      )

    Migration.create_migration_file(repo, "AddOauthPkceFields", content)
  end

  defp ensure_repo(repo, args) do
    Ecto.ensure_repo(repo, args ++ ~w(--no-deps-check))
  end
end
