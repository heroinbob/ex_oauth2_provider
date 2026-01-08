defmodule Mix.Tasks.ExOauth2Provider.AddPkceFieldsTest do
  use ExOauth2Provider.Mix.TestCase
  use ExOauth2Provider.Test.MigrationTasks

  alias ExOauth2Provider.Test.Mix.MigrationRepo
  alias Mix.Tasks.ExOauth2Provider.AddPkceFields

  @options ~w(--repo #{inspect(MigrationRepo)})

  setup do
    clear_migrations!()
    :ok
  end

  describe "run/1" do
    test "generates the migration file with the correct content" do
      File.cd!(@tmp_path, fn ->
        AddPkceFields.run(@options)

        assert filename = get_migration_filename!()
        assert String.match?(filename, ~r/^\d{14}_add_pkce_fields\.exs$/)

        assert get_migration_content!() ==
                 """
                 defmodule #{inspect(MigrationRepo)}.Migrations.AddPkceFields do
                   use Ecto.Migration

                   def change do
                     alter table(:oauth_access_grants) do
                       add :code_challenge, :string
                       add :code_challenge_method, :string
                     end
                   end
                 end
                 """
      end)
    end

    test "supports setting the table name as a command argument" do
      File.cd!(@tmp_path, fn ->
        AddPkceFields.run(@options ++ ~w[--table my_table])
        content = get_migration_content!()

        assert String.contains?(content, "alter table(:my_table) do")
      end)
    end
  end

  test "doesn't create the file when the migration already exists" do
    File.cd!(@tmp_path, fn ->
      AddPkceFields.run(@options)

      assert_raise Mix.Error,
                   "migration can't be created, there is already a migration file with name AddPkceFields.",
                   fn ->
                     AddPkceFields.run(@options)
                   end
    end)
  end
end
