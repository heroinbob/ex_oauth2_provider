defmodule Mix.Tasks.ExOauth2Provider.MigrationTask do
  @moduledoc """
  Logic to support writing simple migrations for DB changes to support
  new features.
  """
  alias Mix.Ecto
  alias Mix.ExOauth2Provider
  alias Mix.ExOauth2Provider.Migration

  @type params :: %{
          required(:command_line_args) => list(),
          required(:context_name) => String.t(),
          required(:template) => String.t(),
          required(:table) => String.t()
        }

  defmacro __using__(_opts) do
    quote do
      use Mix.Task

      import Mix.Tasks.ExOauth2Provider.MigrationTask
    end
  end

  defdelegate parse_args(args, switches, default_opts),
    to: ExOauth2Provider,
    as: :parse_options

  @spec create_migration_file(params :: params()) :: any()
  def create_migration_file(%{command_line_args: args} = params) do
    args
    |> Ecto.parse_repo()
    |> Enum.map(&Ecto.ensure_repo(&1, args ++ ~w(--no-deps-check)))
    |> Enum.map(&Map.put(params, :repo, &1))
    |> Enum.each(&write_content/1)
  end

  defp write_content(%{
         context_name: context_name,
         repo: repo,
         template: template,
         table: table
       }) do
    content =
      EEx.eval_string(
        template,
        migration: %{
          context_name: context_name,
          repo: repo,
          table: table
        }
      )

    Migration.create_migration_file(repo, context_name, content)
  end

  def disallow_in_umbrella!(task_name) do
    ExOauth2Provider.no_umbrella!(task_name)
  end
end
