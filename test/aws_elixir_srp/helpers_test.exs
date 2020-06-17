defmodule AwsElixirSrp.HelpersTest do
  use ExUnit.Case, async: true
  use PropCheck

  alias Export.Python

  alias AwsElixirSrp.Helpers

  def start_python() do
    {:ok, py} = Python.start(python_path: Path.expand("priv/python"))

    py
  end

  def hash_sha256(py, buf) do
    py
    |> Python.call("source", "hash_sha256", [buf])
    |> to_string()
  end

  property "hash_sha256 works" do
    py = start_python()

    forall buf <- binary() do
      Helpers.hash_sha256(buf) == hash_sha256(py, buf)
    end
  end
end
