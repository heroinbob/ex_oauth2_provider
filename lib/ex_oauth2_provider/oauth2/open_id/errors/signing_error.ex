defmodule ExOauth2Provider.OpenId.Errors.SigningError do
  @message "Unable to sign ID Token! Please check the config and verify the algorithm matches your key."

  @type t :: %__MODULE__{
          message: String.t(),
          reason: any()
        }

  defexception [
    :message,
    :reason
  ]

  @spec new(reason :: any()) :: t()
  def new(reason) do
    exception(message: @message, reason: reason)
  end
end
