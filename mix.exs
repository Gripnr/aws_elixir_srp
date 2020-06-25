defmodule AwsElixirSrp.MixProject do
  use Mix.Project

  def project do
    [
      app: :aws_elixir_srp,
      version: "0.1.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:aws, "~> 0.5.0"},
      {:timex, "~> 3.6.1"},
      {:httpoison, "~> 1.6.2", override: true},
      {:export, "~> 0.1.0", only: [:test]},
      {:propcheck, "~> 1.1", only: [:test]}
    ]
  end
end
