defmodule ExOauth2Provider.OpenId.IdToken do
  @moduledoc """
  This builds ID tokens and has very basic support for the `email` claim.
  https://openid.net/specs/openid-connect-core-1_0.html#IDToken

  You can learn more about standard claims available https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

  ## Supported Claims

  * `:email` - When present in scopes of the grant the user's email will be exposed
               in the ID token as well as `:email_verified`.

  Today - we grab claims from scope. The claims attribute is not supported yet.

  https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
  """
  alias ExOauth2Provider.Chrono
  alias ExOauth2Provider.OpenId.Claim
  alias ExOauth2Provider.OpenId.OpenIdConfig
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

  @supported_claims ~w[email]

  def new(access_token, request_context, opts) do
    config = OpenIdConfig.get(opts)

    context = %{
      client: request_context.client,
      config: config,
      grant: request_context.access_grant,
      token: access_token,
      user: access_token.resource_owner
    }

    context
    |> build()
    |> add_claims(context)
    |> add_nonce(context)
  end

  # `:aud` - Audience that is the intended recipient.
  # `:auth_time` - The time (seconds since epoch) that authentication took place.
  # `:exp` - Exp time in number of seconds since epoch.
  # `:iat` - Time the JWT was issued (seconds since epoch)
  # `:iss` - Issuer of the response.
  # `:sub` - Identifier for the end user
  defp build(%{client: client, token: token, user: user} = _context) do
    created_at = Chrono.to_unix(token.inserted_at)
    # TODO: handle nil expiration
    expires_at = created_at + token.expires_in

    # TODO: make audience and iss configurable.
    %{
      aud: "https://veeps.com",
      auth_time: created_at,
      exp: expires_at,
      iat: created_at,
      iss: "https://veeps.com",
      sub: user.id
    }
  end

  # TODO: We only support scopes. More work needs to be done to support
  # reques
  defp add_claims(payload, %{token: token} = context) do
    token
    |> Scopes.from()
    |> Enum.filter(&(&1 in @supported_claims))
    |> Enum.reduce(payload, &add_claim(&1, &2, context))
  end

  defp add_claim(
         name,
         payload,
         %{
           config: %OpenIdConfig{claims: claims},
           user: user
         } = context
       ) do
    case Enum.find(claims, &(&1.name == String.to_existing_atom(name))) do
      %Claim{includes: includes, name: name} = claim ->
        value = Claim.get_value_for(claim, user)

        payload
        |> Map.put(name, value)
        |> add_includes(includes, user)

      nil ->
        payload
    end
  end

  defp add_includes(payload, includes, user) do
    Enum.reduce(
      includes,
      payload,
      fn
        %Claim{name: name} = claim, acc ->
          value = Claim.get_value_for(claim, user)

          Map.put(acc, name, value)
      end
    )
  end

  defp add_nonce(payload, %{grant: grant} = _context) do
    # TODO
    # Map.put(payload, :nonce, grant.open_id_nonce)
    payload
  end
end
