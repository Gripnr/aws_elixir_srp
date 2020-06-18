defmodule AwsElixirSrp.Helpers do
  @moduledoc false

  @n_hex Enum.join(
           [
             "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
             "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
             "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
             "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
             "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
             "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
             "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
             "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
             "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
             "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
             "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64",
             "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
             "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B",
             "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
             "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31",
             "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
           ],
           ""
         )

  @g_hex 2
  @info_bits to_charlist("Caldera Derived Key")

  @spec hash_sha256(charlist) :: charlist
  def hash_sha256(buf) do
    buf
    |> (&:crypto.hash(:sha256, &1)).()
    |> Base.encode16(case: :lower)
    |> String.pad_leading(64, "0")
  end

  @spec hex_hash(charlist) :: {:ok, charlist} | :error
  def hex_hash(hex) do
    plain_hex =
      hex
      |> String.replace(~r/\s/, "")
      |> String.downcase()

    if rem(String.length(plain_hex), 2) == 0 do
      plain_hex
      |> Integer.parse(16)
      |> case do
        {_, ""} ->
          plain_hex
          |> String.to_charlist()
          |> Enum.chunk_every(2)
          |> Enum.map(fn [a, b] ->
            left = if(a >= 97, do: a - 87, else: a - 48)
            right = if(b >= 97, do: b - 87, else: b - 48)

            left * 16 + right
          end)
          |> :binary.list_to_bin()
          |> (&{:ok, hash_sha256(&1)}).()

        _ ->
          :error
      end
    else
      :error
    end
  end

  @spec hex_to_long(charlist) :: {:ok, integer} | :error
  def hex_to_long(hex) do
    hex
    |> Integer.parse(16)
    |> case do
      {value, ""} ->
        {:ok, value}

      _ ->
        :error
    end
  end

  @spec long_to_hex(pos_integer) :: charlist
  def long_to_hex(long) do
    long
    |> Integer.to_charlist(16)
    |> :binary.list_to_bin
    |> String.downcase()
  end
end
