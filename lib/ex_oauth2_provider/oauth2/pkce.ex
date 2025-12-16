defmodule ExOauth2Provider.PKCE do
  @moduledoc """
  Logic to allow working with PKCE in requests.
  """
  alias ExOauth2Provider.{
    Authorization,
    Config,
    PKCE.CodeChallenge,
    PKCE.CodeVerifier
  }

  @settings [
    :all_methods,
    :disabled,
    :plain_only,
    :s256_only
  ]

  @query_param_to_method_lookup %{
    "plain" => :plain,
    "S256" => :s256
  }

  @enabled_settings @settings -- [:disabled]

  @type challenge_method :: :plain | :s256

  @type setting ::
          unquote(
            @settings
            |> Enum.reverse()
            |> Enum.reduce(&quote(do: unquote(&1) | unquote(&2)))
          )

  @type client :: %{pkce: setting()}

  @doc """
  Returns a list of the supported PKCE settings.
  """
  @spec settings() :: setting()
  def settings, do: @settings

  @doc """
  Returns true if PKCE is required. This function requires a list with `:otp_app`
  defined because it checks the config for the app.

  There are three ways to enable PKCE:

  1) Enable it for a single oauth app by setting the `:pkce` field in
     ExOauth2Provider.Applications.Application. This takes precident over config.

  2) Define it in the config for your app. See Config for details. This acts globally.

  3) Add it to the options of the request the same as you would define it in the config.
     This affects a single endpoint/request depending on how you use it.

  ## Options

  - `:otp_app` - If the client PKCE setting is disabled then this is used to determine if the
                otp app's config has PKCE enabled.
  """
  @spec required?(context :: Authorization.context() | client(), config :: list()) :: boolean()
  def required?(%{client: client} = _context, config) do
    determine_pkce_setting(client, config) in @enabled_settings
  end

  def required?(%{pkce: _} = client, config) do
    determine_pkce_setting(client, config) in @enabled_settings
  end

  @doc """
  Validate that the request has the correct code challenge. Do not call this function
  when PKCE is configured as `:disabled`. Be sure to call `required?/1` to verify PKCE
  is enabled prior to calling this function.
  """
  @spec valid?(context :: Authorization.context(), config :: list()) :: boolean()
  def valid?(
        %{
          request: %{"code_challenge" => challenge} = request
        } = context,
        config
      )
      when is_list(config) do
    method = Map.get(request, "code_challenge_method", "plain")

    # We only need to check the format during the authorization phase.
    method_allowed?(method, context, config) and CodeChallenge.valid?(challenge, method)
  end

  # This supports the grant access token step. It accepts the entire context.
  def valid?(%{access_grant: %{code_challenge: nil}}, _config) do
    # A grant was passed in without any PKCE info. This is not valid.
    false
  end

  def valid?(
        %{
          access_grant: %{
            code_challenge: expected_value,
            code_challenge_method: challenge_method
          },
          request: %{
            "code_verifier" => verifier
          }
        } = context,
        config
      ) do
    method_allowed?(challenge_method, context, config) and
      CodeVerifier.valid?(verifier, expected_value, challenge_method)
  end

  def valid?(_invalid_request, _config), do: false

  # Challenge payloads have a string method. Normalize it to make checking easy.
  defp method_allowed?(method, context, config) when is_binary(method) do
    @query_param_to_method_lookup
    |> Map.get(method, :unsupported)
    |> method_allowed?(context, config)
  end

  defp method_allowed?(method, %{client: client} = _context, config) do
    # NOTE: We do not check for :disabled because one shouldn't call valid/2 if PKCE is disabled.
    # One should check using `required?/1` before calling `valid/2`.
    # Let it crash if this is used in an unexpected way. That's a bug on us if so.
    case determine_pkce_setting(client, config) do
      :all_methods -> method in [:plain, :s256]
      :plain_only -> method == :plain
      :s256_only -> method == :s256
    end
  end

  # Defer to config when the app is disabled.
  # Perhaps we can add :none or something and make disabled override config.
  defp determine_pkce_setting(%{pkce: :disabled} = _client, config) do
    Config.pkce_setting(config)
  end

  defp determine_pkce_setting(%{pkce: pkce} = _client, _config), do: pkce
end
