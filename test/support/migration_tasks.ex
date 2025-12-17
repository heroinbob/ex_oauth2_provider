defmodule ExOauth2Provider.Test.MigrationTasks do
  @moduledoc """
  Context that helps test a migration task.
  """
  defmacro __using__(opts) do
    task = Keyword.fetch!(opts, :task)

    quote do
      import ExOauth2Provider.Test.MigrationTasks

      @tmp_path Path.join(["tmp", inspect(unquote(task))])
      @migrations_path Path.join(@tmp_path, "migrations")

      defmodule Repo do
        def __adapter__, do: true

        def config do
          [
            priv: "tmp/#{inspect(unquote(task))}",
            otp_app: :ex_oauth2_provider
          ]
        end
      end

      def clear_migrations! do
        File.rm_rf!(@tmp_path)
        File.mkdir_p!(@tmp_path)
      end

      def get_migration_filename!() do
        @migrations_path |> File.ls!() |> hd()
      end

      def get_migration_content! do
        filename = get_migration_filename!()
        @migrations_path |> Path.join(filename) |> File.read!()
      end
    end
  end
end
