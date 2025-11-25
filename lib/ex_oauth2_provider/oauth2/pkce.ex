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

  1) Define it in the config for your app via `:use_pkce`
  2) Add it to the options of the request via `with: :pkce`
  """
  @spec required?(config :: list()) :: boolean()
  def required?(config) when is_list(config) do
    opts = config[:with]

    opts == :pkce or (is_list(opts) and :pkce in opts) or Config.use_pkce?(config)
  end

  @doc """
  Validate that the request has the correct code challenge.
  """
  @spec valid?(context_or_request_params :: map()) :: boolean()
  @spec valid?(context_or_request_params :: map(), config :: list()) :: boolean()
  def valid?(context_or_request, config \\ [])

  def valid?(%{"code_challenge" => challenge} = request, config) when is_list(config) do
    method = Map.get(request, "code_challenge_method", "plain")

    # We only need to check the format during the authorization phase.
    method_allowed?(method, config[:allow]) and CodeChallenge.valid?(challenge, method)
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
    method_allowed?(method, config[:allow]) and
      CodeVerifier.valid?(verifier, expected_value, method)
  end

  def valid?(_invalid_request, _config), do: false

  # Challenge payloads have a string method. Normalize it to make checking easy.
  defp method_allowed?(method, allow) when is_binary(method) do
    @method_lookup
    |> Map.get(method, :unsupported)
    |> method_allowed?(allow)
  end

  defp method_allowed?(:plain, allow) when allow in [:plain, nil] do
    true
  end

  defp method_allowed?(:s256, allow) when allow in [:s256, nil] do
    true
  end

  defp method_allowed?(:plain, allow) when is_list(allow) do
    :plain in allow
  end

  defp method_allowed?(:s256, allow) when is_list(allow) do
    :s256 in allow
  end

  # There is either an unsupported method or allow is incorrect.
  defp method_allowed?(_method, _allow), do: false
end
