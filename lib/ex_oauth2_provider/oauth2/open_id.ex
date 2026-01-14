defmodule ExOauth2Provider.OpenId do
  @moduledoc """
  Logic to allow working with Open ID.
  """
  alias ExOauth2Provider.OpenId.IdToken
  alias ExOauth2Provider.Scopes

  @open_id_scope "openid"

  def generate_id_token(access_token, context, config) do
    IdToken.new(access_token, context, config)
  end

  def in_scope?(scopes) when is_binary(scopes) do
    scopes
    |> Scopes.to_list()
    |> in_scope?()
  end

  def in_scope?(scopes) when is_list(scopes), do: @open_id_scope in scopes
end
