defmodule ExOauth2Provider.OpenId.IdToken do
  @moduledoc """
  This builds ID tokens and has very basic support for the `email` claim.
  https://openid.net/specs/openid-connect-core-1_0.html#IDToken

  You can learn more about standard claims available https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

  ## Configuration

  The ID token requires some configuration and offers some optional things to configure
  as well.

  Required

  * `:issuer`

  Optional

  * `:claims`            - The additional claims that the token supports.
  * `:id_token_lifespan` - The number of seconds that the token is valid for.

  ## Basic Claims

  * `:aud` - Audience that is the intended recipient - the Application uid.
  * `:auth_time` - The time (seconds since epoch) that authentication took place.
  * `:exp` - Exp time in number of seconds since epoch.
  * `:iat` - Time the JWT was issued (seconds since epoch)
  * `:iss` - Issuer of the response.
  * `:sub` - Identifier for the end user

  ## Other Claims

  Additional claims are supported and the data is currently extracted from the
  user record associated to the token.

  The way it works is simple:

  1. Ensure your claim is defined as a scope on the application
  2. Define the scope (and any nested included scopes) in your app config.

  When a request is processed all scopes are reviewed to see if any match
  the defined claims in the app config. If so - then the matching value
  is pulled from the user record.

  You can also define an alias for the claim if it is named something different
  in the user record.

  More complicated behavior can be added as needed such as data coercion, etc.
  Just ask!

  https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
  """
  alias ExOauth2Provider.AccessTokens.AccessToken
  alias ExOauth2Provider.Chrono
  alias ExOauth2Provider.OpenId
  alias ExOauth2Provider.OpenId.Claim
  alias ExOauth2Provider.OpenId.OpenIdConfig
  alias ExOauth2Provider.Scopes

  def new(%JOSE.JWT{fields: fields}) do
    %{
      aud: fields["aud"],
      auth_time: fields["auth_time"],
      exp: fields["exp"],
      iat: fields["iat"],
      iss: fields["iss"],
      sub: fields["sub"]
    }
  end

  @spec new(access_token :: AccessToken.t(), request_context :: map(), opts :: keyword()) ::
          OpenId.id_token()
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

  defp build(
         %{
           client: client,
           config: %OpenIdConfig{
             id_token_issuer: issuer,
             id_token_lifespan: lifespan
           },
           token: token,
           user: user
         } = _context
       ) do
    created_at = Chrono.to_unix(token.inserted_at)
    expires_at = created_at + lifespan

    %{
      aud: client.uid,
      auth_time: created_at,
      exp: expires_at,
      iat: created_at,
      iss: issuer,
      sub: user.id
    }
  end

  # TODO: We only support scopes. More work needs to be done to support
  # request "claims" param.
  defp add_claims(payload, %{token: token} = context) do
    token
    |> Scopes.from()
    |> Enum.reduce(payload, &add_claim(&1, &2, context))
  end

  defp add_claim(
         name,
         payload,
         %{
           config: %OpenIdConfig{claims: claims},
           user: user
         } = _context
       ) do
    case find_claim(claims, name) do
      %Claim{includes: includes, name: name} = claim ->
        value = Claim.get_value_for!(claim, user)

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
          value = Claim.get_value_for!(claim, user)

          Map.put(acc, name, value)
      end
    )
  end

  defp add_nonce(payload, %{grant: grant} = _context) do
    case grant do
      %{open_id_nonce: nonce} when is_binary(nonce) ->
        Map.put(payload, :nonce, nonce)

      _none ->
        payload
    end
  end

  # Since we search for claims by scope - we must be able to handle
  # non existent atoms. If one configures a claim then the atom
  # will exist so we need to weed out non existent claims.
  defp find_claim(claims, name) do
    Enum.find(
      claims,
      fn claim ->
        try do
          claim.name == String.to_existing_atom(name)
        rescue
          _non_existent_atom -> false
        end
      end
    )
  end
end
