defmodule ExOauth2Provider.PKCE do
  @moduledoc """
  Logic to allow working with PKCE in requests.
  """
  alias ExOauth2Provider.{
    Config,
    PKCE.CodeChallenge,
    PKCE.CodeVerifier
  }

  @method_lookup %{
    "plain" => :plain,
    "S256" => :s256
  }

  @doc """
  Returns true if PKCE is required. This function requires a list with `:otp_app`
  defined because it checks the config for the app.

  There are two ways to enable PKCE:

  1) Define it in the config for your app. See Config for details.
  2) Add it to the options of the request the same as you would define it in the config.
  """
  @spec required?(config :: list()) :: boolean()
  defdelegate required?(config), to: Config, as: :use_pkce?

  @doc """
  Validate that the request has the correct code challenge. Do not call this function
  when PKCE is configured as `:disabled`. Be sure to call `required?/1` to verify PKCE
  is enabled prior to calling this function.
  """
  @spec valid?(context_or_request_params :: map(), config :: list()) :: boolean()
  def valid?(%{"code_challenge" => challenge} = request, config) when is_list(config) do
    method = Map.get(request, "code_challenge_method", "plain")

    # We only need to check the format during the authorization phase.
    method_allowed?(method, config) and CodeChallenge.valid?(challenge, method)
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
            code_challenge_method: method
          },
          request: %{
            "code_verifier" => verifier
          }
        },
        config
      ) do
    method_allowed?(method, config) and CodeVerifier.valid?(verifier, expected_value, method)
  end

  def valid?(_invalid_request, _config), do: false

  # Challenge payloads have a string method. Normalize it to make checking easy.
  defp method_allowed?(method, config) when is_binary(method) do
    @method_lookup
    |> Map.get(method, :unsupported)
    |> method_allowed?(config)
  end

  # NOTE: We do not check for :disabled because one shouldn't call valid/2 if PKCE is disabled.
  # Let it crash if this is used in an unexpected way. That's a bug on us if so.
  defp method_allowed?(method, config) do
    case Config.pkce_option(config) do
      :enabled -> method in [:plain, :s256]
      :plain_only -> method == :plain
      :s256_only -> method == :s256
    end
  end
end
