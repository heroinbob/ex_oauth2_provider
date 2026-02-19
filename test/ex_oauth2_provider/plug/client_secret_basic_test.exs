defmodule ExOauth2Provider.Plug.ClientSecretBasicTest do
  use ExOauth2Provider.ConnCase

  alias ExOauth2Provider.Plug.ClientSecretBasic

  @unauthenticated {
    401,
    [
      {"cache-control", "max-age=0, private, must-revalidate"},
      {"content-type", "text/plain; charset=utf-8"}
    ],
    "Unauthenticated"
  }

  describe "init/1" do
    test "returns the value when given a map" do
      value = %{on_error: :fart}
      assert ClientSecretBasic.init(value) == value
    end

    test "returns a map when given a keyword" do
      assert ClientSecretBasic.init(on_error: :shout) == %{on_error: :shout}
    end
  end

  describe "call/2" do
    test "returns the conn when the id/secret are valid" do
      token = Base.encode64("abc:xyz")

      conn =
        :post
        |> Plug.Test.conn("/token")
        |> Plug.Conn.put_req_header("authorization", "Basic #{token}")

      assert %Plug.Conn{} = conn = ClientSecretBasic.call(conn, %{})

      refute conn.halted
      assert conn.assigns.client_id == "abc"
      assert conn.assigns.client_secret == "xyz"
    end

    test "returns unauthenticated when the header value isn't present" do
      conn = Plug.Test.conn(:post, "/token")

      assert %Plug.Conn{} = conn = ClientSecretBasic.call(conn, %{})

      assert conn.halted
      assert Plug.Test.sent_resp(conn) == @unauthenticated
    end

    test "returns unauthenticated when the value isn't base64 encoded" do
      conn =
        :post
        |> Plug.Test.conn("/token")
        |> Plug.Conn.put_req_header("authorization", "Bearer token")

      assert %Plug.Conn{} = conn = ClientSecretBasic.call(conn, %{})

      assert conn.halted
      assert Plug.Test.sent_resp(conn) == @unauthenticated
    end

    test "returns unauthenticated when the decoded value isn't formatted correctly" do
      for value <- ~w[abcxyz abc-xyz] do
        token = Base.encode64(value)

        conn =
          :post
          |> Plug.Test.conn("/token")
          |> Plug.Conn.put_req_header("authorization", "Basic #{token}")

        assert %Plug.Conn{} = conn = ClientSecretBasic.call(conn, %{})

        assert conn.halted
        assert Plug.Test.sent_resp(conn) == @unauthenticated
      end
    end
  end

  describe "call/2 when given :noop as :on_error option" do
    test "noops when the header value isn't present" do
      conn = Plug.Test.conn(:post, "/token")

      assert %Plug.Conn{} = conn = ClientSecretBasic.call(conn, %{on_error: :noop})

      refute conn.halted
    end

    test "noops when the value isn't base64 encoded" do
      conn =
        :post
        |> Plug.Test.conn("/token")
        |> Plug.Conn.put_req_header("authorization", "Bearer token")

      assert %Plug.Conn{} = conn = ClientSecretBasic.call(conn, %{on_error: :noop})

      refute conn.halted
    end

    test "noops when the decoded value isn't formatted correctly" do
      for value <- ~w[abcxyz abc-xyz] do
        token = Base.encode64(value)

        conn =
          :post
          |> Plug.Test.conn("/token")
          |> Plug.Conn.put_req_header("authorization", "Basic #{token}")

        assert %Plug.Conn{} = conn = ClientSecretBasic.call(conn, %{on_error: :noop})

        refute conn.halted
      end
    end
  end
end
