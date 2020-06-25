defmodule AwsElixirSrp.Client do
  @moduledoc false

  @type t :: __MODULE__

  defstruct [
    :username,
    :password,
    :user_pool_id,
    :client_id,
    :client_secret,
    :big_n,
    :g,
    :k,
    :small_a_value,
    :large_a_value
  ]
end
