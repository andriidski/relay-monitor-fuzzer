package builder

type BuilderBidFaultOption struct {
	Enabled bool `yaml:"enabled"`
	Rate    int  `yaml:"rate"`
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
