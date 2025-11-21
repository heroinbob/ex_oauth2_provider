defmodule ExOauth2Provider.ConfigTest do
  # Do not use async in here. Some tests make config changes.
  use ExUnit.Case
  alias ExOauth2Provider.Config

  setup do
    config = Application.get_env(:ex_oauth2_provider, ExOauth2Provider)

    on_exit(fn ->
      Application.put_env(:ex_oauth2_provider, ExOauth2Provider, config)
    end)
  end

  test "repo/1" do
    assert Config.repo(otp_app: :my_app) == Dummy.Repo

    Application.delete_env(:ex_oauth2_provider, ExOauth2Provider)
    Application.put_env(:my_app, ExOauth2Provider, repo: Dummy.Repo)

    assert Config.repo(otp_app: :my_app) == Dummy.Repo

    Application.delete_env(:my_app, ExOauth2Provider)

    assert_raise RuntimeError, ~r/config :my_app, ExOauth2Provider/, fn ->
      Config.repo(otp_app: :my_app)
    end

    assert_raise RuntimeError, ~r/config :ex_oauth2_provider, ExOauth2Provider/, fn ->
      Config.repo([])
    end
  end

  describe "use_pkce?/1" do
    test "returns true when the otp app is set to use_pkce" do
      assert Config.use_pkce?(otp_app: :ex_oauth2_provider, use_pkce: true) == true
      assert Config.use_pkce?(otp_app: :ex_oauth2_provider, use_pkce: "true") == false
      assert Config.use_pkce?(otp_app: :ex_oauth2_provider, use_pkce: nil) == false
      assert Config.use_pkce?(otp_app: :ex_oauth2_provider) == false

      # Verify it grabs from the app env
      Application.put_env(:my_app, ExOauth2Provider, use_pkce: true)
      assert Config.use_pkce?(otp_app: :my_app) == true

      Application.put_env(:my_app, ExOauth2Provider, use_pkce: "true")
      assert Config.use_pkce?(otp_app: :my_app) == false
    end
  end
end
