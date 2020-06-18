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


  property "hash_sha256/1 works" do
    py = start_python()

    forall buf <- binary() do
      Helpers.hash_sha256(buf) == py_hash_sha256(py, buf)
    end
  end

  property "hex_hash/1 works" do
    py = start_python()

    forall hex <- non_empty(hex_gen) do
      Helpers.hex_hash(hex) == {:ok, py_hex_hash(py, hex)}
    end
  end

  property "hex_to_long/1 works" do
    py = start_python()

    forall hex <- non_empty(hex_gen) do
      Helpers.hex_to_long(hex) == {:ok, py_hex_to_long(py, hex)}
    end
  end

  property "long_to_hex/1 works" do
    py = start_python()

    forall n <- pos_integer() do
       Helpers.long_to_hex(n)  == py_long_to_hex(py, n)
    end
  end
end
