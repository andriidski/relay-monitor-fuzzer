package fuzzer

import (
	"github.com/andriidski/rm-builder-fuzzer/pkg/api"
	"github.com/andriidski/rm-builder-fuzzer/pkg/builder"
)

type FuzzerConfig struct {
	BuilderBidFaultConfig builder.BuilderBidFaultConfig `yaml:"builder_bid_fault"`
}

type NetworkConfig struct {
	Name               string `yaml:"name"`
	GenesisForkVersion string `yaml:"genesis_fork_version"`
}

type ConsensusConfig struct {
	Endpoint string `yaml:"endpoint"`
}

type BuilderConfig struct {
	SecretKey string `yaml:"secret_key"`
}

type Config struct {
	Network   *NetworkConfig   `yaml:"network"`
	Consensus *ConsensusConfig `yaml:"consensus"`
	API       *api.APIConfig   `yaml:"api"`
	Builder   *BuilderConfig   `yaml:"builder"`
	Fuzzer    *FuzzerConfig    `yaml:"fuzzer"`
}
