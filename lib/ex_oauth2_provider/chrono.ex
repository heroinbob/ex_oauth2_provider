defmodule ExOauth2Provider.Chrono do
  @moduledoc """
  Help to support manipulating several kinds of date/time structs.
  """
  @unix_epoch ~N[1970-01-01 00:00:00]

  @spec add_time(DateTime.t() | NaiveDateTime.t(), atom()) :: non_neg_integer()
  def add_time(value, seconds, unit \\ :second)

  def add_time(%DateTime{} = value, seconds, unit) do
    DateTime.add(value, seconds, unit)
  end

  def add_time(%NaiveDateTime{} = value, seconds, unit) do
    NaiveDateTime.add(value, seconds, unit)
  end

  @spec to_unix(DateTime.t() | NaiveDateTime.t()) :: non_neg_integer()
  def to_unix(%DateTime{} = value) do
    DateTime.to_unix(value)
  end

  def to_unix(%NaiveDateTime{} = value) do
    NaiveDateTime.diff(value, @unix_epoch)
  end

  @spec unix_now() :: non_neg_integer()
  def unix_now do
    to_unix(DateTime.utc_now())
  end
end
