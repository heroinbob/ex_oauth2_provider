defmodule Mix.Tasks.ExOauth2Provider.AddOpenIdConstraintsToGrantsTest do
  use ExOauth2Provider.Mix.TestCase
  use ExOauth2Provider.Test.MigrationTasks

  alias ExOauth2Provider.Test.Mix.MigrationRepo
  alias Mix.Tasks.ExOauth2Provider.AddOpenIdConstraints

  @options ~w(--repo #{inspect(MigrationRepo)})

  setup do
    clear_migrations!()
    :ok
  end

  describe "run/1" do
    test "generates the migration file with the correct content" do
      File.cd!(@tmp_path, fn ->
        AddOpenIdConstraints.run(@options)

        assert filename = get_migration_filename!()
        assert String.match?(filename, ~r/^\d{14}_add_open_id_constraints\.exs$/)

        assert get_migration_content!() ==
                 """
                   defmodule #{inspect(MigrationRepo)}.Migrations.AddOpenIdConstraints do
                   use Ecto.Migration

                   def change do
                     create unique_index(:oauth_access_grants, [:code_challenge])
                     create unique_index(:oauth_access_grants, [:open_id_nonce])
                   end
                 end
                 """
      end)
    end

    test "supports setting the table name as a command argument" do
      File.cd!(@tmp_path, fn ->
        AddOpenIdConstraints.run(@options ++ ~w[--table my_table])
        content = get_migration_content!()

        assert String.contains?(content, "create unique_index(:my_table, [:code_challenge])")
        assert String.contains?(content, "create unique_index(:my_table, [:open_id_nonce])")
      end)
    end
  end

  test "doesn't create the file when the migration already exists" do
    File.cd!(@tmp_path, fn ->
      AddOpenIdConstraints.run(@options)

      assert_raise Mix.Error,
                   "migration can't be created, there is already a migration file with name AddOpenIdConstraints.",
                   fn ->
                     AddOpenIdConstraints.run(@options)
                   end
    end)
  end
end
