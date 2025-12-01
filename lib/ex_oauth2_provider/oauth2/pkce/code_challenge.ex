defmodule ExOauth2Provider.PKCE.CodeChallenge do
  alias ExOauth2Provider.PKCE.CodeVerifier

  @plain_method "plain"
  @sha_method "S256"
  # 256 / 8
  @sha256_byte_size 32

  @doc """
  Determine if the give challenge is valid based on the code challenge method.

  ## Plain

  Check to make sure that the verifier has the proper format and size.

  ## S256

  The challenge should be a Base64 url encoded string that is the sha256 hash
  of the code verifier that will be presented in exchange for the access token.
  """
  @spec valid?(challenge :: String.t(), method :: String.t()) :: boolean()
  def valid?(challenge, @plain_method) do
    # Plain challenges are the code verifier.
    CodeVerifier.valid_format?(challenge)
  end

  def valid?(challenge, @sha_method) do
    case Base.url_decode64(challenge, padding: false) do
      {:ok, decoded} ->
        byte_size(decoded) == @sha256_byte_size

      :error ->
        false
    end
  end
end
