defmodule ExOauth2Provider.Test.PKCE do
  @moduledoc """
  Logic for working with code challenges and verifiers.
  """

  @doc """
  Generate a code verifier for use with PKCE requests. Never go below 32
  as it takes a minimum of 32 octets to generate a 43 char encoded string.

  See Appendix A for a good explanation of the format of the verifier and
  the challenge.

  https://datatracker.ietf.org/doc/html/rfc7636#appendix-A
  """
  def generate_code_verifier(opts \\ %{}) do
    num_bytes = Map.get(opts, :num_bytes, 32)

    num_bytes
    |> :crypto.strong_rand_bytes()
    |> encode()
  end

  @doc """
  Generate a new code verifier and a challenge.
  """
  def generate_code_challenge(opts \\ %{}) do
    method = Map.get(opts, :method, :s256)
    num_bytes = Map.get(opts, :num_bytes, 32)
    verifier = generate_code_verifier(%{num_bytes: num_bytes})

    generate_code_challenge(verifier, method)
  end

  @doc """
  Generate a new challenge from the given verifier.
  """
  def generate_code_challenge(verifier, :plain), do: verifier

  def generate_code_challenge(verifier, :s256) do
    :sha256
    |> :crypto.hash(verifier)
    |> encode()
  end

  @doc """
  Generate a Base64 encoded string per the PKCE RFC
  """
  def encode(value), do: Base.url_encode64(value, padding: false)
end
