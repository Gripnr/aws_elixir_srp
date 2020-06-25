defmodule AwsElixirSrp.HelpersTest do
  use ExUnit.Case, async: true
  use PropCheck

  alias Export.Python

  alias AwsElixirSrp.Helpers

  def start_python() do
    {:ok, py} = Python.start(python_path: Path.expand("priv/python"))

    py
  end

  def hex_gen() do
    let bytes <- list(byte()) do
      bytes
      |> Enum.map(fn byte ->
        byte
        |> Integer.to_string(16)
        |> String.pad_leading(2, "0")
      end)
      |> Enum.join("")
    end
  end

  def ascii_string() do
    let bytes <- list(range(0, 127)) do
      :binary.list_to_bin(bytes)
    end
  end

  def py_hash_sha256(py, buf) do
    py
    |> Python.call("source", "hash_sha256", [buf])
    |> to_string()
  end

  def py_hex_hash(py, hex) do
    py
    |> Python.call("source", "hex_hash", [hex])
    |> to_string()
  end

  def py_hex_to_long(py, hex) do
    py
    |> Python.call("source", "hex_to_long", [hex])
  end

  def py_long_to_hex(py, long) do
    py
    |> Python.call("source", "long_to_hex", [long])
    |> to_string()
  end

  def py_get_random(py, nbytes) do
    py
    |> Python.call("source", "get_random", [nbytes])
  end

  def py_pad_hex(py, bytes) do
    py
    |> Python.call("source", "pad_hex", [bytes])
    |> to_string()
  end

  def py_compute_hkdf(py, ikdf, salt) do
    py
    |> Python.call("source", "compute_hkdf", [ikdf, salt])
    |> to_string()
  end

  def py_calculate_u(py, big_a, big_b) do
    py
    |> Python.call("source", "calculate_u", [big_a, big_b])
  end

  def py_get_secret_hash(py, username, client_id, client_secret) do
    py
    |> Python.call("source", "AWSSRP.get_secret_hash", [username, client_id, client_secret])
    |> to_string()
  end

  def py_pow_rem(py, n, p, r) do
    py
    |> Python.call("builtins", "pow", [n, p, r])
  end

  property "hash_sha256/1 works" do
    py = start_python()

    forall buf <- binary() do
      Helpers.hash_sha256(buf) == py_hash_sha256(py, buf)
    end
  end

  property "hex_hash/1 works" do
    py = start_python()

    forall hex <- non_empty(hex_gen()) do
      Helpers.hex_hash(hex) == {:ok, py_hex_hash(py, hex)}
    end
  end

  property "hex_to_long/1 works" do
    py = start_python()

    forall hex <- non_empty(hex_gen()) do
      Helpers.hex_to_long(hex) == {:ok, py_hex_to_long(py, hex)}
    end
  end

  property "long_to_hex/1 wrorks" do
    py = start_python()

    forall n <- pos_integer() do
      Helpers.long_to_hex(n) == py_long_to_hex(py, n)
    end
  end

  property "get_random/1 works" do
    forall n <- range(0, 100) do
      Helpers.get_random(n) < floor(:math.pow(256, n))
    end

    py = start_python()

    forall bin <- non_empty(binary()) do
      Helpers.get_random(bin) >= py_get_random(py, bin)
    end
  end

  property "pad_hex/1 works" do
    py = start_python()

    forall n <- pos_integer() do
      Helpers.pad_hex(n) >= py_pad_hex(py, n)
    end
  end

  property "compute_hkdf/2 works" do
    py = start_python()

    forall [ikm <- binary(), salt <- binary()] do
      Helpers.compute_hkdf(ikm, salt) == py_compute_hkdf(py, ikm, salt)
    end
  end

  property "calculate_u/2 works" do
    py = start_python()

    forall [big_a <- pos_integer(), big_b <- pos_integer()] do
      Helpers.calculate_u(big_a, big_b) == {:ok, py_calculate_u(py, big_a, big_b)}
    end
  end

  property "get_auth_params/2 works" do
    py = start_python()

    forall [
      username <- ascii_string(),
      client_id <- ascii_string(),
      client_secret <- ascii_string()
    ] do
      Helpers.get_secret_hash(username, client_id, client_secret) ==
        py_get_secret_hash(py, username, client_id, client_secret)
    end
  end

  property "pow_rem/3 works" do
    py = start_python()

    forall [
      n <- integer(),
      p <- pos_integer(),
      r <- pos_integer()
    ] do
      Helpers.pow_rem(n, p, r) == py_pow_rem(py, n, p, r)
    end
  end
end
