defmodule ExOauth2Provider.Test.ConfigChanges do
  alias ExOauth2Provider.Test.OpenId

  defmacro __using__(_opts) do
    quote do
      import ExOauth2Provider.Test.ConfigChanges

      setup do
        config = Application.get_env(:ex_oauth2_provider, ExOauth2Provider)

        on_exit(fn ->
          Application.put_env(:ex_oauth2_provider, ExOauth2Provider, config)
        end)
      end
    end
  end

  @doc """
  Replace the current config with the given changes.
  """
  def put_env_change(changes, app \\ :ex_oauth2_provider, key \\ ExOauth2Provider)
      when is_list(changes) do
    original = Application.get_env(app, key)

    changed =
      Enum.reduce(
        changes,
        original,
        fn {k, v}, acc ->
          Keyword.put(acc, k, v)
        end
      )

    Application.put_env(app, key, changed)
  end

  @doc """
  Replace values in the existing OpenId config. This allows you to change the open ID
  config but also retain what already is configured.
  """
  def add_open_id_changes(changes, app \\ :ex_oauth2_provider, key \\ ExOauth2Provider) do
    original = OpenId.get_app_config()
    changed = Map.merge(original, changes)

    put_env_change([open_id: changed], app, key)
  end
end
