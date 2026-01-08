defmodule Mix.Tasks.ExOauth2Provider.AddOpenIdToApplicationsTest do
  use ExOauth2Provider.Mix.TestCase
  use ExOauth2Provider.Test.MigrationTasks

  alias ExOauth2Provider.Test.Mix.MigrationRepo
  alias Mix.Tasks.ExOauth2Provider.AddOpenIdToApplications

  @options ~w(--repo #{inspect(MigrationRepo)})

  setup do
    clear_migrations!()
    :ok
  end

  describe "run/1" do
    test "generates the migration file with the correct content" do
      File.cd!(@tmp_path, fn ->
        AddOpenIdToApplications.run(@options)

        assert filename = get_migration_filename!()
        assert String.match?(filename, ~r/^\d{14}_add_open_id_to_applications\.exs$/)

        assert get_migration_content!() ==
                 """
                   defmodule #{inspect(MigrationRepo)}.Migrations.AddOpenIdToApplications do
                   use Ecto.Migration

                   def change do
                     alter table(:oauth_applications) do
                       add :open_id_settings, :map
                     end
                   end
                 end
                 """
      end)
    end

    test "supports setting the table name as a command argument" do
      File.cd!(@tmp_path, fn ->
        AddOpenIdToApplications.run(@options ++ ~w[--table my_table])
        content = get_migration_content!()

        assert String.contains?(content, "alter table(:my_table) do")
      end)
    end
  end

  test "doesn't create the file when the migration already exists" do
    File.cd!(@tmp_path, fn ->
      AddOpenIdToApplications.run(@options)

      assert_raise Mix.Error,
                   "migration can't be created, there is already a migration file with name AddOpenIdToApplications.",
                   fn ->
                     AddOpenIdToApplications.run(@options)
                   end
    end)
  end
end
