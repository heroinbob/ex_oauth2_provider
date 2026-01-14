defmodule ExOauth2Provider.ChronoTest do
  use ExUnit.Case, async: true

  alias ExOauth2Provider.Chrono

  describe "add_time/2" do
    test "adds seconds to a given DateTime struct" do
      assert Chrono.add_time(~U[2026-01-14 16:53:00Z], 42) == ~U[2026-01-14 16:53:42Z]
    end

    test "adds seconds to a given NaiveDateTime struct" do
      assert Chrono.add_time(~N[2026-01-14 16:53:00Z], 42) == ~N[2026-01-14 16:53:42Z]
    end
  end

  describe "add_time/3" do
    test "adds the given unit to a given struct" do
      assert Chrono.add_time(~U[2026-01-14 16:53:00Z], 1, :hour) == ~U[2026-01-14 17:53:00Z]
    end
  end

  describe "to_unix/2" do
    test "converts a DateTime struct" do
      assert Chrono.to_unix(~U[2026-01-14 16:53:00Z]) == 1_768_409_580
    end

    test "converts a NaiveDateTime struct" do
      assert Chrono.to_unix(~N[2026-01-14 16:53:00Z]) == 1_768_409_580
    end
  end
end
