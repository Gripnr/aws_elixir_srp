defmodule AwsElixirSrp.MixProject do
  use Mix.Project

  def project do
    [
      app: :aws_elixir_srp,
      version: "0.1.0",
      elixir: "~> 1.14",
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
      {:aws, "~> 0.13.0"},
      {:hackney, "~> 1.18.1"},
      {:export, "~> 0.1.0", only: [:test]},
      {:propcheck, "~> 1.4.1", only: [:test]},
      {:timex, "~> 3.7.11"}
    ]
  end
end
