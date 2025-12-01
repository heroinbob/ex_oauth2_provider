defmodule ExOauth2Provider.PKCE.CodeVerifier do
  @code_verifier_regex ~r/^[[:alnum:]._~-]{43,128}$/

  @doc """
  Returs true if the verifier has a valid format per RFC.
  """
  @spec valid_format?(verifier :: String.t()) :: boolean()
  def valid_format?(verifier) when is_binary(verifier) do
    verifier =~ @code_verifier_regex
  end

  def valid_format?(_verifier), do: false

  @doc """
  Return true if the verifier is valid.

  ## Plain

  It just needs to match the given challenge.

  ## S256

  It must match the challenge after created an SHA256 hash
  and then base64url-encoding it.
  """
  @spec valid?(
          verifier :: String.t(),
          challenge :: String.t(),
          method :: :plain | :s256
        ) :: boolean()
  def valid?(verifier, challenge, :plain) do
    Plug.Crypto.secure_compare(verifier, challenge)
  end

  def valid?(verifier, challenge, :s256) do
    :sha256
    |> :crypto.hash(verifier)
    |> Base.url_encode64(padding: false)
    |> Plug.Crypto.secure_compare(challenge)
  end

  # Method is not supported.
  def valid?(_verifier, _challenge, _method), do: false
end
