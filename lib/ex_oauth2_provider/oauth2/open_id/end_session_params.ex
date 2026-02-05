defmodule ExOauth2Provider.OpenId.EndSessionParams do
  use Ecto.Schema

  alias Ecto.Changeset
  alias ExOauth2Provider.Applications
  alias ExOauth2Provider.OpenId.OpenIdConfig
  alias ExOauth2Provider.OpenId.Signatures

  @castable [:id_token_hint, :post_logout_redirect_uri, :state, :user_id]
  @required [:id_token_hint, :user_id]

  embedded_schema do
    field(:app, :map)
    field(:id_token, :map)
    field(:id_token_hint, :string)
    field(:post_logout_redirect_uri, :string)
    field(:state, :string)
    field(:user_id, :string)
  end

  def parse_request_params(
        %{"user_id" => user_id} = request_params,
        %OpenIdConfig{} = config,
        opts
      )
      when is_list(opts) do
    request_params = Map.put(request_params, "user_id", stringify(user_id))

    %__MODULE__{}
    |> Changeset.cast(request_params, @castable)
    |> Changeset.validate_required(@required)
    |> verify_signature(config)
    |> verify_application(opts)
    |> verify_issuer(config.id_token_issuer)
    |> verify_sub()
    |> verify_post_logout_redirect_uri()
    |> Changeset.apply_action(:validate)
    |> case do
      {:ok, _params} = result ->
        result

      {:error, changeset} ->
        {:error, Changeset.traverse_errors(changeset, &elem(&1, 0))}
    end
  end

  defp verify_signature(changeset, open_id_config) do
    if changeset.errors[:id_token_hint] == nil do
      hint = Changeset.get_field(changeset, :id_token_hint)

      case Signatures.verify(hint, open_id_config) do
        {:ok, token} ->
          Changeset.put_change(changeset, :id_token, token)

        _error ->
          Changeset.add_error(changeset, :id_token_hint, "is invalid")
      end
    else
      changeset
    end
  end

  defp verify_application(changeset, opts) do
    %{aud: aud} = Changeset.get_change(changeset, :id_token, %{aud: nil})

    # Double ampersand short circuits so you either get false, nil or a struct.
    case is_binary(aud) && Applications.get_application(aud, opts) do
      %{uid: _} = app ->
        Changeset.put_change(changeset, :app, app)

      _ ->
        Changeset.add_error(changeset, :aud, "is invalid")
    end
  end

  defp verify_issuer(changeset, expected_issuer) do
    %{iss: iss} = Changeset.get_change(changeset, :id_token, %{iss: nil})

    if iss == expected_issuer do
      changeset
    else
      Changeset.add_error(changeset, :iss, "is invalid")
    end
  end

  defp verify_sub(changeset) do
    user_id = Changeset.get_change(changeset, :user_id)
    # Remember - sub is the user ID and those records can have an int type.
    %{sub: sub} = Changeset.get_change(changeset, :id_token, %{sub: nil})

    if not is_nil(sub) and stringify(sub) == user_id do
      changeset
    else
      Changeset.add_error(changeset, :sub, "is invalid")
    end
  end

  defp verify_post_logout_redirect_uri(changeset) do
    request_uri = Changeset.get_change(changeset, :post_logout_redirect_uri)

    %{open_id_post_logout_redirect_uri: app_uri} =
      Changeset.get_change(
        changeset,
        :app,
        %{open_id_post_logout_redirect_uri: nil}
      )

    if app_uri == request_uri do
      changeset
    else
      Changeset.add_error(changeset, :post_logout_redirect_uri, "is invalid")
    end
  end

  # This is designed to handle int and binary resource owner IDs.
  # Crash if something unexpected is given.
  defp stringify(value) do
    cond do
      is_binary(value) -> value
      is_integer(value) -> Integer.to_string(value)
    end
  end
end
