defmodule ExOauth2Provider.PKCE do
  @moduledoc """
  Logic to allow working with PKCE in requests.
  """
  alias ExOauth2Provider.{
    Config,
    PKCE.CodeChallenge,
    PKCE.CodeVerifier
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
  def valid?(%{"code_challenge" => challenge} = request) do
    method = Map.get(request, "code_challenge_method", "plain")

    # We only need to check the format during the authorization phase.
    CodeChallenge.valid?(challenge, method)
  end

  # This supports the grant access token step. It accepts the entire context.
  def valid?(%{access_grant: %{code_challenge: nil}}) do
    # A grant was passed in without any PKCE info. This is not valid.
    false
  end

  def valid?(%{
        access_grant: %{
          code_challenge: expected_value,
          code_challenge_method: method
        },
        request: %{
          "code_verifier" => verifier
        }
      }) do
    CodeVerifier.valid?(verifier, expected_value, method)
  end

  def valid?(_invalid_request), do: false
end
