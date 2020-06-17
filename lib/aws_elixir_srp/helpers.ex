defmodule AwsElixirSrp.Helpers do
  @moduledoc false

  def hash_sha256(buf) do
    buf
    |> (&:crypto.hash(:sha256, &1)).()
    |> Base.encode16(case: :lower)
    |> String.pad_leading(64, "0")
  end
end
