defmodule AwsElixirSrp.Helpers do
  @moduledoc false

  @info_bits "Caldera Derived Key"

  @spec hash_sha256(charlist) :: charlist
  def hash_sha256(buf) do
    buf
    |> (&:crypto.hash(:sha256, &1)).()
    |> Base.encode16(case: :lower)
    |> String.pad_leading(64, "0")
  end

  @spec from_hex(charlist) :: {:ok, binary} | :error
  def from_hex(hex) do
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
            left = if(a >= ?a, do: a - ?a + 10, else: a - ?0)
            right = if(b >= ?a, do: b - ?a + 10, else: b - ?0)

            left * 16 + right
          end)
          |> :binary.list_to_bin()
          |> (&{:ok, &1}).()

        _ ->
          :error
      end
    else
      :error
    end
  end

  @spec hex_hash(charlist) :: {:ok, charlist} | :error
  def hex_hash(hex) do
    case from_hex(hex) do
      {:ok, value} ->
        {:ok, hash_sha256(value)}

      error ->
        error
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
    |> :binary.list_to_bin()
    |> String.downcase()
  end

  @spec get_random(pos_integer | binary) :: charlist
  def get_random(n) when is_integer(n) do
    n
    |> :crypto.strong_rand_bytes()
    |> get_random()
  end

  def get_random(bin) when is_binary(bin) do
    :binary.decode_unsigned(bin)
  end

  @spec pad_hex(pos_integer | binary) :: charlist
  def pad_hex(n) when is_integer(n) do
    n
    |> long_to_hex
    |> pad_hex()
  end

  def pad_hex(hex) when is_binary(hex) do
    case hex do
      hex when rem(byte_size(hex), 2) == 1 ->
        <<?0, hex::binary>>

      <<first::size(8), _rest::binary>> when first in [?8, ?9, ?a, ?b, ?c, ?d, ?e, ?f] ->
        <<?0, ?0, hex::binary>>

      hex ->
        hex
    end
  end

  @spec compute_hkdf(binary, binary) :: binary
  def compute_hkdf(ikm, salt) do
    prk = :crypto.hmac(:sha256, salt, ikm)
    info_bits_update = @info_bits <> <<1>>
    hmac_hash = :crypto.hmac(:sha256, prk, info_bits_update)

    binary_part(hmac_hash, 0, 16)
  end

  @spec calculate_u(pos_integer, pos_integer) :: {:ok, pos_integer} | :error
  def calculate_u(big_a, big_b) do
    case hex_hash(pad_hex(big_a) <> pad_hex(big_b)) do
      {:ok, u_hex_hash} ->
        hex_to_long(u_hex_hash)

      error ->
        error
    end
  end

  @spec get_secret_hash(charlist, charlist, charlist) :: charlist
  def get_secret_hash(username, client_id, client_secret) do
    message = username <> client_id
    hmac_obj = :crypto.hmac(:sha256, client_secret, message)

    Base.encode64(hmac_obj)
  end

  @spec pow_rem(integer, pos_integer, pos_integer) :: integer
  def pow_rem(n, p, r) do
    if n < 0 do
      q = div(p, 2)
      n2 = n * n

      init = pow_rem(n2, q, r)

      if rem(p, 2) == 1 do
        t2 = rem(n, r) + r

        rem(init * t2, r)
      else
        init
      end
    else
      :binary.decode_unsigned(:crypto.mod_pow(n, p, r))
    end
  end
end
