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

  import Mix.Tasks.ExOauth2Provider.MigrationTask

  @context_name "AddPkceFields"
  @switches [table: :string]
  @default_opts [table: "oauth_access_grants"]
  @mix_task "ex_oauth2_provider.add_pkce_fields"

  @template """
  defmodule <%= inspect repo %>.Migrations.AddPkceFields do
    use Ecto.Migration

    def change do
      alter table(:<%= table %>) do
        add :code_challenge, :string
        add :code_challenge_method, :string
      end
    end
  end
  """

  @impl true
  def run(args) do
    disallow_in_umbrella!(@mix_task)

    args
    |> parse_args(@switches, @default_opts)
    |> Map.merge(%{
      command_line_args: args,
      context_name: @context_name,
      template: @template
    })
    |> create_migration_file()
  end
end
