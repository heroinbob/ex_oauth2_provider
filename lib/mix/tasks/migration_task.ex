defmodule Mix.Tasks.ExOauth2Provider.MigrationTask do
  alias Mix.{
    Ecto,
    ExOauth2Provider,
    ExOauth2Provider.Migration
  }

  def create_migration_file(%{
        command_line_args: args,
        context_name: context_name,
        table: table,
        template: template
      }) do
    repo = get_repo(args)

    content =
      EEx.eval_string(
        template,
        context_name: context_name,
        repo: repo,
        table: table
      )

    Migration.create_migration_file(repo, context_name, content)
  end

  def disallow_in_umbrella!(mix_task) do
    ExOauth2Provider.no_umbrella!(mix_task)
  end

  defp get_repo(command_line_args) do
    command_line_args
    |> Ecto.parse_repo()
    |> hd()
    |> Ecto.ensure_repo(command_line_args ++ ~w(--no-deps-check))
  end

  def parse_args(args, switches, defaults) do
    args |> ExOauth2Provider.parse_options(switches, defaults) |> elem(0)
  end
end
