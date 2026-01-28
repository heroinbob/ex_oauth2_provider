defmodule Mix.Tasks.ExOauth2Provider.AddOpenIdConstraints do
  @shortdoc "Generates migration for adding constraints to the open ID fields"

  @moduledoc """
  Generates a migration file that adds open_id_nonce to the access grants table.

      # Update the default table which is `oauth_access_grants`
      mix ex_oauth2_provider.add_open_id_constraints -r MyApp.Repo

      # Update your custom table name if you used another one
      mix ex_oauth2_provider.add_open_id_constraints -r MyApp.Repo --table some_other_name

  This generator will add the oauth2 migration file in `priv/repo/migrations`.

  The repository must be set under `:ecto_repos` in the current app
  configuration or given via the `-r` option.

  By default, the migration will be generated to the
  "priv/YOUR_REPO/migrations" directory of the current application but it
  can be configured to be any subdirectory of `priv` by specifying the
  `:priv` key under the repository configuration.

  If you have an umbrella application then you must execute this within
  the target app directory. You can't execute this within an umbrella at
  the root.

  ## Arguments

    * `-r`, `--repo` - the repo module
    * `--table` - The name of the table to modify
  """
  use Mix.Task

  import Mix.Tasks.ExOauth2Provider.MigrationTask

  @context_name "AddOpenIdConstraints"
  @default_opts [table: "oauth_access_grants"]
  @mix_task "ex_oauth2_provider.add_open_id_constraints"
  @switches [table: :string]

  @template """
    defmodule <%= inspect repo %>.Migrations.AddOpenIdConstraints do
    use Ecto.Migration

    def change do
      create unique_index(:<%= table %>, [:code_challenge])
      create unique_index(:<%= table %>, [:open_id_nonce])
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
