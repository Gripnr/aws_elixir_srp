defmodule AwsElixirSrp do
  @moduledoc false

  alias AWS
  alias HTTPoison
  alias Timex
  alias Timex.Format.DateTime.Formatters.Strftime, as: TimexFormat

  alias AwsElixirSrp.{Client, Helpers}

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
  @g_hex "2"

  defp generate_random_small_a(big_n) do
    random_long_int = Helpers.get_random(128)

    rem(random_long_int, big_n)
  end

  defp calculate_a(g, small_a_value, big_n) do
    big_a = Helpers.pow_rem(g, small_a_value, big_n)

    if rem(big_a, big_n) == 0 do
      raise RuntimeError, "Safety check for A failed"
    else
      big_a
    end
  end

  @spec create(charlist, charlist, charlist, charlist) :: Client.t()
  def create(username, password, pool_id, client_id) do
    {:ok, big_n} = Helpers.hex_to_long(@n_hex)
    {:ok, g} = Helpers.hex_to_long(@g_hex)
    {:ok, k_hex} = Helpers.hex_hash("00" <> @n_hex <> "0" <> @g_hex)
    {:ok, k} = Helpers.hex_to_long(k_hex)
    small_a_value = generate_random_small_a(big_n)

    %Client{
      username: username,
      password: password,
      user_pool_id: pool_id,
      client_id: client_id,
      big_n: big_n,
      g: g,
      k: k,
      small_a_value: small_a_value,
      large_a_value: calculate_a(g, small_a_value, big_n)
    }
  end

  defp get_pool_id(%Client{user_pool_id: user_pool_id}) do
    [_region, pool_id] = String.split(user_pool_id, "_")

    pool_id
  end

  defp get_region(%Client{user_pool_id: user_pool_id}) do
    [region, _pool_id] = String.split(user_pool_id, "_")

    region
  end

  defp get_auth_params(%Client{
         username: username,
         large_a_value: large_a_value,
         client_secret: client_secret,
         client_id: client_id
       }) do
    auth_params = %{
      "USERNAME" => username,
      "SRP_A" => Helpers.long_to_hex(large_a_value)
    }

    if client_secret do
      Map.put(
        auth_params,
        "SECRET_HASH",
        Helpers.get_secret_hash(username, client_id, client_secret)
      )
    else
      auth_params
    end
  end

  @spec get_password_authentication_key(Client.t(), charlist, charlist, pos_integer(), charlist) ::
          charlist
  def get_password_authentication_key(
        %Client{
          g: g,
          k: k,
          big_n: big_n,
          large_a_value: large_a_value,
          small_a_value: small_a_value
        } = client,
        username,
        password,
        server_b_value,
        salt
      ) do
    {:ok, u_value} = Helpers.calculate_u(large_a_value, server_b_value)

    if u_value == 0 do
      raise RuntimeError, "U cannot be zero."
    end

    username_password = "#{get_pool_id(client)}#{username}:#{password}"
    username_password_hash = Helpers.hash_sha256(username_password)

    {:ok, x_value_hex} = Helpers.hex_hash(Helpers.pad_hex(salt) <> username_password_hash)
    {:ok, x_value} = Helpers.hex_to_long(x_value_hex)

    g_mod_pow_xn = Helpers.pow_rem(g, x_value, big_n)
    int_value2 = server_b_value - k * g_mod_pow_xn
    s_value = Helpers.pow_rem(int_value2, small_a_value + u_value * x_value, big_n)
    u_value_hex = Helpers.pad_hex(Helpers.long_to_hex(u_value))
    s_value_hex = Helpers.pad_hex(s_value)

    {:ok, s_value_bytes} = Helpers.from_hex(s_value_hex)
    {:ok, u_value_bytes} = Helpers.from_hex(u_value_hex)

    Helpers.compute_hkdf(s_value_bytes, u_value_bytes)
  end

  @spec process_challenge(Client.t(), map) :: map
  def process_challenge(
        %Client{
          username: username,
          password: password,
          client_id: client_id,
          client_secret: client_secret
        } = client,
        params
      ) do
    %{
      "SALT" => salt_hex,
      "SECRET_BLOCK" => secret_block_b64,
      "SRP_B" => srp_b_hex,
      "USERNAME" => username,
      "USER_ID_FOR_SRP" => user_id_for_srp
    } = params

    timestamp =
      "Thu Jun 25 03:46:51 UTC 2020" ||
        TimexFormat.format!(Timex.now(), "%a %b %d %H:%M:%S UTC %Y")

    {:ok, srp_b} = Helpers.hex_to_long(srp_b_hex)
    hkdf = get_password_authentication_key(client, user_id_for_srp, password, srp_b, salt_hex)

    {:ok, secret_block_bytes} = Base.decode64(secret_block_b64)

    msg = "#{get_pool_id(client)}#{user_id_for_srp}#{secret_block_bytes}#{timestamp}"

    hmac_obj = :crypto.hmac(:sha256, hkdf, msg)

    signature_string = Base.encode64(hmac_obj)

    response = %{
      "TIMESTAMP" => timestamp,
      "USERNAME" => user_id_for_srp,
      "PASSWORD_CLAIM_SECRET_BLOCK" => secret_block_b64,
      "PASSWORD_CLAIM_SIGNATURE" => signature_string
    }

    if client_secret do
      Map.put(
        response,
        "SECRET_HASH",
        Helpers.get_secret_hash(username, client_id, client_secret)
      )
    else
      response
    end
  end

  @spec authenticate_user(Client.t()) :: {:ok, charlist} | {:error, any}
  def authenticate_user(%Client{user_pool_id: user_pool_id, client_id: client_id} = client) do
    region = get_region(client)
    aws_client = %AWS.Client{region: region, secret_access_key: "", endpoint: "amazonaws.com"}

    auth_params = get_auth_params(client)

    with {:ok,
          %{
            "ChallengeName" => "PASSWORD_VERIFIER",
            "ChallengeParameters" => challenge_parameters
          },
          %HTTPoison.Response{}} <-
           AWS.Cognito.IdentityProvider.initiate_auth(
             aws_client,
             %{
               "AuthFlow" => "USER_SRP_AUTH",
               "AuthParameters" => auth_params,
               "ClientId" => client_id
             },
             []
           ),
         challenge_response = process_challenge(client, challenge_parameters),
         {:ok, token_response, %HTTPoison.Response{}} <-
           AWS.Cognito.IdentityProvider.respond_to_auth_challenge(
             aws_client,
             %{
               "ClientId" => client_id,
               "ChallengeName" => "PASSWORD_VERIFIER",
               "ChallengeResponses" => challenge_response
             },
             []
           ) do
      {:ok, token_response}
    else
      {:ok, response, _} -> {:error, :response_invalid, response}
    end
  rescue
    MatchError -> {:error, :response_invalid, nil}
  end
end
