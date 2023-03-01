package types

import (
	"github.com/flashbots/go-boost-utils/types"
	"github.com/holiman/uint256"
)

type (
	Slot                        = uint64
	Epoch                       = uint64
	ForkVersion                 = types.ForkVersion
	Uint256                     = uint256.Int
	PublicKey                   = types.PublicKey
	Hash                        = types.Hash
	Bid                         = types.SignedBuilderBid
	Root                        = types.Root
	ValidatorIndex              = uint64
	SignedValidatorRegistration = types.SignedValidatorRegistration
	SignedBlindedBeaconBlock    = types.SignedBlindedBeaconBlock
)
