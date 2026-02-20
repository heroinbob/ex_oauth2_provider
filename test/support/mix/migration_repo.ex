defmodule ExOauth2Provider.Test.Mix.MigrationRepo do
  @moduledoc """
  Basic context to simulate a repo for testing migrations with.
  """
  def __adapter__, do: true

  def config,
    do: [
      priv: "tmp/ex_oauth2_provider",
      otp_app: :ex_oauth2_provider
    ]
end
