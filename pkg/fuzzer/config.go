package fuzzer

import (
	"strings"

	"github.com/andriidski/rm-builder-fuzzer/pkg/api"
	"github.com/andriidski/rm-builder-fuzzer/pkg/builder"
)

type FuzzerConfig struct {
	BuilderBidFaultConfig builder.BuilderBidFaultConfig `yaml:"builder_bid_fault"`
	Versions              []string                      `yaml:"versions"`
}

type NetworkConfig struct {
	Name               string `yaml:"name"`
	Version            string `yaml:"version"`
	GenesisForkVersion string `yaml:"genesis_fork_version"`
}

func (c *NetworkConfig) String() string {
	var str strings.Builder
	str.WriteString("NetworkConfig{")
	str.WriteString("Name: ")
	str.WriteString(c.Name)
	str.WriteString(", Version: ")
	str.WriteString(c.Version)
	str.WriteString(", GenesisForkVersion: ")
	str.WriteString(c.GenesisForkVersion)
	str.WriteString("}")
	return str.String()
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
