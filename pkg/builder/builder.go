package builder

import (
	"context"
	"math/big"
	"math/rand"
	"time"

	"github.com/andriidski/rm-builder-fuzzer/pkg/consensus"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/beacon"
	coreTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"

	"go.uber.org/zap"
)

type Builder struct {
	logger *zap.SugaredLogger

	// Can be used by builder to lookup the actual state from CL.
	consensusClient *consensus.Client
	clock           *consensus.Clock

	// Configuration for creating blocks. This determines how many "faults"
	// the builder will include in the block.
	bidFaultConfig *BuilderBidFaultConfig

	builderSecretKey     *bls.SecretKey
	builderPublicKey     boostTypes.PublicKey
	builderSigningDomain boostTypes.Domain
}

func New(bidFaultConfig *BuilderBidFaultConfig, consensusClient *consensus.Client, clock *consensus.Clock, sk *bls.SecretKey, builderSigningDomain boostTypes.Domain, logger *zap.SugaredLogger) *Builder {

	pkBytes := bls.PublicKeyFromSecretKey(sk).Compress()
	pk := boostTypes.PublicKey{}
	pk.FromSlice(pkBytes)

	// Seed the random number generator with the current time
	rand.Seed(time.Now().UnixNano())

	return &Builder{
		consensusClient:      consensusClient,
		clock:                clock,
		bidFaultConfig:       bidFaultConfig,
		builderSecretKey:     sk,
		builderPublicKey:     pk,
		builderSigningDomain: builderSigningDomain,
		logger:               logger,
	}
}

func roll(rate int) bool {
	return rand.Intn(101) <= rate
}

func (builder *Builder) getSecretKey() *bls.SecretKey {
	signatureConfig := builder.bidFaultConfig.Signature

	if signatureConfig.Enabled && roll(signatureConfig.Rate) {
		b, err := hexutil.Decode("0x0000000000000000000000000000000000000000000000000000000000000000")
		if err != nil {
			builder.logger.Fatalw("incorrect bad secret key")
		}
		badSecretKey, err := bls.SecretKeyFromBytes(b[:])
		if err != nil {
			builder.logger.Fatalw("build not create bad secret key", "err", err)
		}
		builder.logger.Infow("using bad secret key", "badSecretKey", badSecretKey)
		return badSecretKey
	} else {
		return builder.builderSecretKey
	}
}

func (builder *Builder) getPublicKey() boostTypes.PublicKey {
	publicKeyConfig := builder.bidFaultConfig.PublicKey

	if publicKeyConfig.Enabled && roll(publicKeyConfig.Rate) {
		badPublicKey, err := boostTypes.HexToPubkey("0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
		if err != nil {
			builder.logger.Fatalw("could not create bad public key", "err", err)
		}
		builder.logger.Infow("using bad public key", "badPublicKey", badPublicKey)
		return badPublicKey
	} else {
		return builder.builderPublicKey
	}
}

func (builder *Builder) getParentHash(slot uint64) boostTypes.Hash {
	parentHashConfig := builder.bidFaultConfig.ParentHash
	badParentHash := boostTypes.Hash{0x00, 0x00}

	if parentHashConfig.Enabled && roll(parentHashConfig.Rate) {
		builder.logger.Infow("using bad parent hash", "badParentHash", badParentHash)
		return badParentHash
	} else {
		parentHash, err := builder.consensusClient.GetParentHash(context.Background(), slot)
		if err != nil {
			builder.logger.Errorw("could not get parent hash", "err", err)
			return badParentHash
		}
		return parentHash
	}
}

func (builder *Builder) getRandom(slot uint64) boostTypes.Hash {
	randao := builder.bidFaultConfig.Randao
	badRandom := boostTypes.Hash{0x00, 0x00}
	if randao.Enabled && roll(randao.Rate) {
		builder.logger.Infow("using bad random", "badRandom", badRandom)
		return badRandom
	} else {
		random, err := builder.consensusClient.GetRandomnessForProposal(slot)
		if err != nil {
			builder.logger.Errorw("could not get randomness", "err", err)
			return badRandom
		}
		return random
	}
}

func (builder *Builder) getBlockNumber(slot uint64) uint64 {
	blockNumberConfig := builder.bidFaultConfig.BlockNumber
	badBlockNumber := uint64(0)

	if blockNumberConfig.Enabled && roll(blockNumberConfig.Rate) {
		builder.logger.Infow("using bad block number", "badBlockNumber", badBlockNumber)
		return badBlockNumber
	} else {
		blockNumber, err := builder.consensusClient.GetBlockNumberForProposal(slot)
		if err != nil {
			builder.logger.Errorw("could not get block number", "err", err)
			return badBlockNumber
		}
		return blockNumber
	}
}

func (builder *Builder) getTimestamp(slot uint64) int64 {
	timestampConfig := builder.bidFaultConfig.Timestamp
	badTimestamp := int64(0)
	if timestampConfig.Enabled && roll(timestampConfig.Rate) {
		builder.logger.Infow("using bad timestamp", "badTimestamp", badTimestamp)
		return badTimestamp
	} else {
		return builder.clock.SlotInSeconds(slot)
	}
}

func (builder *Builder) generateExecutableData(slot uint64) *beacon.ExecutableDataV1 {
	return &beacon.ExecutableDataV1{
		ParentHash:   common.Hash(builder.getParentHash(slot)),
		FeeRecipient: common.HexToAddress("0x0000000000000000000000000000000000000000"),
		StateRoot:    common.Hash{0x07, 0x16},
		ReceiptsRoot: common.Hash{0x08, 0x20},
		LogsBloom:    coreTypes.Bloom{}.Bytes(),
		Random:       common.Hash(builder.getRandom(slot)),
		Number:       builder.getBlockNumber(slot),
		GasLimit:     uint64(100),
		GasUsed:      uint64(50),
		Timestamp:    uint64(builder.getTimestamp(slot)),
		ExtraData:    hexutil.MustDecode("0x0042fafc"),

		BaseFeePerGas: big.NewInt(16),

		BlockHash:    common.HexToHash("0xca4147f0d4150183ece9155068f34ee3c375448814e4ca557d482b1d40ee5407"),
		Transactions: [][]byte{},
	}
}

func (builder *Builder) executableDataToExecutionPayload(data *beacon.ExecutableDataV1) (*boostTypes.ExecutionPayload, error) {
	transactionData := make([]hexutil.Bytes, len(data.Transactions))
	for i, tx := range data.Transactions {
		transactionData[i] = hexutil.Bytes(tx)
	}

	baseFeePerGas := new(boostTypes.U256Str)
	err := baseFeePerGas.FromBig(data.BaseFeePerGas)
	if err != nil {
		return nil, err
	}

	return &boostTypes.ExecutionPayload{
		ParentHash:    [32]byte(data.ParentHash),
		FeeRecipient:  [20]byte(data.FeeRecipient),
		StateRoot:     [32]byte(data.StateRoot),
		ReceiptsRoot:  [32]byte(data.ReceiptsRoot),
		LogsBloom:     boostTypes.Bloom(coreTypes.BytesToBloom(data.LogsBloom)),
		Random:        [32]byte(data.Random),
		BlockNumber:   data.Number,
		GasLimit:      data.GasLimit,
		GasUsed:       data.GasUsed,
		Timestamp:     data.Timestamp,
		ExtraData:     data.ExtraData,
		BaseFeePerGas: *baseFeePerGas,
		BlockHash:     [32]byte(data.BlockHash),
		Transactions:  transactionData,
	}, nil
}

func (builder *Builder) getExecutionPayload(slot uint64) (*boostTypes.ExecutionPayload, error) {
	return builder.executableDataToExecutionPayload(builder.generateExecutableData(slot))
}

func (builder *Builder) getValue() (*boostTypes.U256Str, error) {
	value := new(boostTypes.U256Str)
	err := value.FromBig(big.NewInt(0))
	if err != nil {
		builder.logger.Errorf("could not set block value", "err", err)
		return nil, err
	}

	return value, nil
}

func (builder *Builder) GetSignedBuilderBid(slot uint64, parentHashHex string, proposerPubkeyHex string) (*boostTypes.SignedBuilderBid, error) {
	bid, err := builder.GetBuilderBid(slot, parentHashHex, proposerPubkeyHex)
	if err != nil {
		builder.logger.Errorf("could not get bid", "err", err)
		return nil, err
	}

	signature, err := boostTypes.SignMessage(bid, builder.builderSigningDomain, builder.getSecretKey())
	if err != nil {
		builder.logger.Errorf("could not sign bid", "err", err)
		return nil, err
	}

	return &boostTypes.SignedBuilderBid{
		Signature: signature,
		Message:   bid,
	}, nil
}

func (builder *Builder) GetBuilderBid(slot uint64, parentHashHex string, proposerPubkeyHex string) (*boostTypes.BuilderBid, error) {
	// Generate some execution payload.
	executionPayload, err := builder.getExecutionPayload(slot)
	if err != nil {
		return nil, err
	}

	// Generate some block value.
	value, err := builder.getValue()
	if err != nil {
		return nil, err
	}

	// Convert the execution payload to a payload header.
	header, err := boostTypes.PayloadToPayloadHeader(executionPayload)
	if err != nil {
		return nil, err
	}

	builderBid := boostTypes.BuilderBid{
		Value:  *value,
		Header: header,
		Pubkey: builder.getPublicKey(),
	}

	return &builderBid, nil
}
