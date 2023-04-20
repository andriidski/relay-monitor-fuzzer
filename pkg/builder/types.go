package builder

import (
	"fmt"
	"strings"
)

type BuilderBidFaultOption struct {
	Enabled     bool    `yaml:"enabled"`
	Probability float64 `yaml:"probability"`
}

func (c *BuilderBidFaultOption) String() string {
	var str strings.Builder
	str.WriteString("BuilderBidFaultOption{")
	str.WriteString("Enabled: ")
	str.WriteString(fmt.Sprintf("%t", c.Enabled))
	if c.Enabled {
		str.WriteString(", Probability: ")
		str.WriteString(fmt.Sprintf("%f", c.Probability))
	}
	str.WriteString("}")
	return str.String()
}

type BuilderBidFaultConfig struct {
	PublicKey   BuilderBidFaultOption `yaml:"public_key"`
	Signature   BuilderBidFaultOption `yaml:"signature"`
	ParentHash  BuilderBidFaultOption `yaml:"parent_hash"`
	Randao      BuilderBidFaultOption `yaml:"randao"`
	BlockNumber BuilderBidFaultOption `yaml:"block_number"`
	GasLimit    BuilderBidFaultOption `yaml:"gas_limit"`
	Timestamp   BuilderBidFaultOption `yaml:"timestamp"`
	Basefee     BuilderBidFaultOption `yaml:"basefee"`
}

func (c *BuilderBidFaultConfig) String() string {
	var str strings.Builder
	str.WriteString("BuilderBidFaultConfig{")
	str.WriteString("PublicKey: ")
	str.WriteString(c.PublicKey.String())
	str.WriteString(", Signature: ")
	str.WriteString(c.Signature.String())
	str.WriteString(", ParentHash: ")
	str.WriteString(c.ParentHash.String())
	str.WriteString(", Randao: ")
	str.WriteString(c.Randao.String())
	str.WriteString(", BlockNumber: ")
	str.WriteString(c.BlockNumber.String())
	str.WriteString(", GasLimit: ")
	str.WriteString(c.GasLimit.String())
	str.WriteString(", Timestamp: ")
	str.WriteString(c.Timestamp.String())
	str.WriteString(", Basefee: ")
	str.WriteString(c.Basefee.String())
	str.WriteString("}")
	return str.String()
}
