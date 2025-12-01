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

  describe "pkce_option/1" do
    test "returns :disabled by default" do
      assert Config.pkce_option([]) == :disabled
    end

    test "returns the value from the given config when supported" do
      for value <- [:disabled, :enabled, :plain_only, :s256_only] do
        assert Config.pkce_option(pkce: value) == value
      end
    end

    test "returns the value from the app config when supported" do
      for value <- [:disabled, :enabled, :plain_only, :s256_only] do
        Application.put_env(:my_app, ExOauth2Provider, pkce: value)

        assert Config.pkce_option(otp_app: :my_app) == value
      end
    end

    test "raises an error when given an unsupported value" do
      assert_raise ArgumentError,
                   "pkce must be one of :disabled | :enabled | :plain_only | :s256_only",
                   fn ->
                     assert Config.pkce_option(pkce: :foo)
                   end

      assert_raise ArgumentError,
                   "pkce must be one of :disabled | :enabled | :plain_only | :s256_only",
                   fn ->
                     Application.put_env(:my_app, ExOauth2Provider, pkce: :foo)

                     assert Config.pkce_option(otp_app: :my_app)
                   end
    end
  end

  describe "use_pkce?/1" do
    test "returns true when the otp app is set to use_pkce" do
      config = [otp_app: :ex_oauth2_provider]
      assert Config.use_pkce?(pkce: :enabled) == true
      assert Config.use_pkce?(pkce: :plain_only) == true
      assert Config.use_pkce?(pkce: :s256_only) == true
      assert Config.use_pkce?(pkce: :disabled) == false
      assert Config.use_pkce?(config) == false

      # Verify it grabs from the app env
      Application.put_env(:my_app, ExOauth2Provider, pkce: :enabled)
      assert Config.use_pkce?(otp_app: :my_app) == true

      Application.put_env(:my_app, ExOauth2Provider, pkce: :disabled)
      assert Config.use_pkce?(otp_app: :my_app) == false
    end
  end
end
