defmodule ExOauth2Provider.OpenId do
  @moduledoc """
  Logic to allow working with Open ID.
  """
  alias ExOauth2Provider.OpenId.OpenIdSettings
  alias ExOauth2Provider.Scopes

  @enabled_policies OpenIdSettings.enforcement_policies() -- [:disabled]

  def enabled?(
        %{
          client: %{
            open_id_settings: %OpenIdSettings{enforcement_policy: policy}
          }
        } = _context
      ) do
    policy in @enabled_policies
  end

  def enabled?(_), do: false

  def valid?(
        %{
          client: %{
            open_id_settings: %OpenIdSettings{enforcement_policy: policy}
          },
          request: %{"scope" => scope}
        } = _context
      ) do
    scopes = Scopes.to_list(scope)

    cond do
      policy == :always and "openid" not in scopes -> false
      true -> true
    end
  end

  def valid?(%{request: %{"scope" => scope}}) do
    # There is no enforcement policy so it's considered disabled here.
    "openid" not in Scopes.to_list(scope)
  end

  def valid?(_), do: false
end
