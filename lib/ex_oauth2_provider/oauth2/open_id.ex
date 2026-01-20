defmodule ExOauth2Provider.OpenId do
  @moduledoc """
  Logic to allow working with Open ID.
  """
  alias ExOauth2Provider.OpenId.IdToken
  alias ExOauth2Provider.Schema
  alias ExOauth2Provider.Scopes

  @type id_token :: %{
          required(:aud) => String.t(),
          required(:exp) => non_neg_integer(),
          required(:iat) => non_neg_integer(),
          required(:iss) => String.t(),
          required(:sub) => String.t(),
          optional(:auth_time) => non_neg_integer(),
          optional(:email) => String.t(),
          optional(:email_verified) => boolean(),
          optional(:nonce) => String.t()
        }

  @open_id_scope "openid"

  @spec fetch_nonce(request_params :: map()) :: {:ok, String.t()} | :not_found
  def fetch_nonce(request_params) do
    case request_params do
      %{"nonce" => nonce} -> {:ok, nonce}
      _ -> :not_found
    end
  end

  @spec generate_id_token(
          access_token :: Schema.t(),
          context :: map(),
          config :: keyword()
        ) :: id_token()
  def generate_id_token(access_token, context, config) do
    IdToken.new(access_token, context, config)
  end

  @spec in_scope?(scopes :: [String.t()] | String.t()) :: boolean()
  def in_scope?(scopes) when is_binary(scopes) do
    scopes
    |> Scopes.to_list()
    |> in_scope?()
  end

  def in_scope?(scopes) when is_list(scopes), do: @open_id_scope in scopes

  def in_scope?(_), do: false
end
