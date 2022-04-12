defmodule ExOauth2Provider.Behaviors.TokenAuthentication do
  @moduledoc """
  Simple behavior for defining a custom token authentication strategy.
  """

  @callback authenticate_token(token :: binary(), config :: keyword()) ::
              {:ok, map()} | {:error, any()}
end
