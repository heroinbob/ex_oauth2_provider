defmodule ExOauth2Provider.Test.ConfigChanges do
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

  def put_env_change(config, app \\ :ex_oauth2_provider, key \\ ExOauth2Provider) do
    Application.put_env(app, key, config)
  end
end
