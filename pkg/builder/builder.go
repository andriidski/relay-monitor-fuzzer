package builder

import (
	"context"
	"fmt"
	"math/big"
	"math/rand"
	"time"

	"github.com/andriidski/relay-monitor-fuzzer/pkg/consensus"
	"github.com/andriidski/relay-monitor-fuzzer/pkg/types"
	"github.com/attestantio/go-builder-client/api/bellatrix"
	capella "github.com/attestantio/go-builder-client/api/capella"
	builderspec "github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	utilbellatrix "github.com/attestantio/go-eth2-client/util/bellatrix"
	utilcapella "github.com/attestantio/go-eth2-client/util/capella"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/beacon"
	coreTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/holiman/uint256"

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

	logger.Infow("using builder with public key", "pk", pk.String())

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

func roll(prob float64) bool {
	return rand.Float64() < prob
}

func (builder *Builder) getSecretKey() *bls.SecretKey {
	signatureConfig := builder.bidFaultConfig.Signature

	if signatureConfig.Enabled && roll(signatureConfig.Probability) {
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

	if publicKeyConfig.Enabled && roll(publicKeyConfig.Probability) {
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

	if parentHashConfig.Enabled && roll(parentHashConfig.Probability) {
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
	if randao.Enabled && roll(randao.Probability) {
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

	if blockNumberConfig.Enabled && roll(blockNumberConfig.Probability) {
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
	if timestampConfig.Enabled && roll(timestampConfig.Probability) {
		builder.logger.Infow("using bad timestamp", "badTimestamp", badTimestamp)
		return badTimestamp
	} else {
		return builder.clock.SlotInSeconds(slot)
	}
}

func (builder *Builder) getBaseFee(slot uint64) *types.Uint256 {
	basefeeConfig := builder.bidFaultConfig.Basefee
	badBasefee := uint256.NewInt(0)

	if basefeeConfig.Enabled && roll(basefeeConfig.Probability) {
		builder.logger.Infow("using bad base fee", "badBasefee", badBasefee.String())
		return badBasefee
	} else {
		expectedBaseFee, err := builder.consensusClient.GetBaseFeeForProposal(slot)
		if err != nil {
			builder.logger.Errorw("could not get base fee", "err", err)
			return badBasefee
		}
		return expectedBaseFee
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

		BaseFeePerGas: big.NewInt(0).SetBytes(builder.getBaseFee(slot).Bytes()),

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

func (builder *Builder) getExecutionPayloadBellatrix(slot uint64) (*consensusbellatrix.ExecutionPayload, error) {
	data := builder.generateExecutableData(slot)
	payload, err := builder.executableDataToExecutionPayload(data)
	if err != nil {
		return nil, err
	}

	transactions := make([]consensusbellatrix.Transaction, len(payload.Transactions))
	for i, tx := range payload.Transactions {
		transactions[i] = consensusbellatrix.Transaction(tx)
	}

	return &consensusbellatrix.ExecutionPayload{
		ParentHash:    phase0.Hash32(payload.ParentHash),
		FeeRecipient:  consensusbellatrix.ExecutionAddress(payload.FeeRecipient),
		StateRoot:     payload.StateRoot,
		ReceiptsRoot:  payload.ReceiptsRoot,
		LogsBloom:     payload.LogsBloom,
		PrevRandao:    payload.Random,
		BlockNumber:   payload.BlockNumber,
		GasLimit:      payload.GasLimit,
		GasUsed:       payload.GasUsed,
		Timestamp:     payload.Timestamp,
		ExtraData:     payload.ExtraData,
		BaseFeePerGas: payload.BaseFeePerGas,
		BlockHash:     phase0.Hash32(payload.BlockHash),
		Transactions:  transactions,
	}, nil
}

func (builder *Builder) getExecutionPayloadCapella(slot uint64) (*consensuscapella.ExecutionPayload, error) {
	data := builder.generateExecutableData(slot)
	payload, err := builder.executableDataToExecutionPayload(data)
	if err != nil {
		return nil, err
	}

	transactions := make([]consensusbellatrix.Transaction, len(payload.Transactions))
	for i, tx := range payload.Transactions {
		transactions[i] = consensusbellatrix.Transaction(tx)
	}

	return &consensuscapella.ExecutionPayload{
		ParentHash:    phase0.Hash32(payload.ParentHash),
		FeeRecipient:  consensusbellatrix.ExecutionAddress(payload.FeeRecipient),
		StateRoot:     payload.StateRoot,
		ReceiptsRoot:  payload.ReceiptsRoot,
		LogsBloom:     payload.LogsBloom,
		PrevRandao:    payload.Random,
		BlockNumber:   payload.BlockNumber,
		GasLimit:      payload.GasLimit,
		GasUsed:       payload.GasUsed,
		Timestamp:     payload.Timestamp,
		ExtraData:     payload.ExtraData,
		BaseFeePerGas: payload.BaseFeePerGas,
		BlockHash:     phase0.Hash32(payload.BlockHash),
		Transactions:  transactions,
	}, nil
}

func (builder *Builder) getValue() *uint256.Int {
	return uint256.NewInt(0)
}

func (builder *Builder) GetSignedBuilderBidBellatrix(slot uint64, parentHashHex string, proposerPubkeyHex string) (bellatrix.SignedBuilderBid, error) {
	bid, err := builder.GetBuilderBidBellatrix(slot, parentHashHex, proposerPubkeyHex)
	if err != nil {
		builder.logger.Errorf("could not get bid", "err", err)
		return bellatrix.SignedBuilderBid{}, err
	}

	signature, err := boostTypes.SignMessage(&bid, builder.builderSigningDomain, builder.getSecretKey())
	if err != nil {
		builder.logger.Errorf("could not sign bid", "err", err)
		return bellatrix.SignedBuilderBid{}, err
	}

	return bellatrix.SignedBuilderBid{
		Message:   &bid,
		Signature: phase0.BLSSignature(signature),
	}, nil
}

func (builder *Builder) GetSignedBuilderBidCapella(slot uint64, parentHashHex string, proposerPubkeyHex string) (capella.SignedBuilderBid, error) {
	bid, err := builder.GetBuilderBidCapella(slot, parentHashHex, proposerPubkeyHex)
	if err != nil {
		builder.logger.Errorf("could not get bid", "err", err)
		return capella.SignedBuilderBid{}, err
	}

	signature, err := boostTypes.SignMessage(&bid, builder.builderSigningDomain, builder.getSecretKey())
	if err != nil {
		builder.logger.Errorf("could not sign bid", "err", err)
		return capella.SignedBuilderBid{}, err
	}

	return capella.SignedBuilderBid{
		Message:   &bid,
		Signature: phase0.BLSSignature(signature),
	}, nil
}

func (builder *Builder) GetSignedBuilderBid(version consensusspec.DataVersion, slot uint64, parentHashHex string, proposerPubkeyHex string) (*builderspec.VersionedSignedBuilderBid, error) {
	switch version {
	case consensusspec.DataVersionBellatrix:
		signedBid, err := builder.GetSignedBuilderBidBellatrix(slot, parentHashHex, proposerPubkeyHex)
		if err != nil {
			return nil, err
		}

		return &builderspec.VersionedSignedBuilderBid{
			Version:   consensusspec.DataVersionCapella,
			Bellatrix: &signedBid,
			Capella:   nil,
		}, nil
	case consensusspec.DataVersionCapella:
		signedBid, err := builder.GetSignedBuilderBidCapella(slot, parentHashHex, proposerPubkeyHex)
		if err != nil {
			return nil, err
		}
		return &builderspec.VersionedSignedBuilderBid{
			Version:   consensusspec.DataVersionBellatrix,
			Bellatrix: nil,
			Capella:   &signedBid,
		}, nil
	default:
		return nil, fmt.Errorf("unknown version: %v", version)
	}
}

func (builder *Builder) GetBuilderBidBellatrix(slot uint64, parentHashHex string, proposerPubkeyHex string) (bellatrix.BuilderBid, error) {
	// Generate some execution payload.
	executionPayload, err := builder.getExecutionPayloadBellatrix(slot)
	if err != nil {
		return bellatrix.BuilderBid{}, err
	}

	// Generate some block value.
	value := builder.getValue()

	// Convert the execution payload to a payload header.
	header, err := BellatrixPayloadToPayloadHeader(executionPayload)
	if err != nil {
		return bellatrix.BuilderBid{}, err
	}

	builderBid := bellatrix.BuilderBid{
		Value:  value,
		Header: header,
		Pubkey: phase0.BLSPubKey(builder.getPublicKey()),
	}

	return builderBid, nil
}

func (builder *Builder) GetBuilderBidCapella(slot uint64, parentHashHex string, proposerPubkeyHex string) (capella.BuilderBid, error) {
	// Generate some execution payload.
	executionPayload, err := builder.getExecutionPayloadCapella(slot)
	if err != nil {
		return capella.BuilderBid{}, err
	}

	// Generate some block value.
	value := builder.getValue()

	// Convert the execution payload to a payload header.
	header, err := CapellaPayloadToPayloadHeader(executionPayload)
	if err != nil {
		return capella.BuilderBid{}, err
	}

	builderBid := capella.BuilderBid{
		Value:  value,
		Header: header,
		Pubkey: phase0.BLSPubKey(builder.getPublicKey()),
	}

	return builderBid, nil
}

func BellatrixPayloadToPayloadHeader(p *consensusbellatrix.ExecutionPayload) (*consensusbellatrix.ExecutionPayloadHeader, error) {
	if p == nil {
		return nil, fmt.Errorf("nil payload")
	}

	transactions := utilbellatrix.ExecutionPayloadTransactions{Transactions: p.Transactions}
	transactionsRoot, err := transactions.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	return &consensusbellatrix.ExecutionPayloadHeader{
		ParentHash:       p.ParentHash,
		FeeRecipient:     p.FeeRecipient,
		StateRoot:        p.StateRoot,
		ReceiptsRoot:     p.ReceiptsRoot,
		LogsBloom:        p.LogsBloom,
		PrevRandao:       p.PrevRandao,
		GasLimit:         p.GasLimit,
		GasUsed:          p.GasUsed,
		Timestamp:        p.Timestamp,
		ExtraData:        p.ExtraData,
		BaseFeePerGas:    p.BaseFeePerGas,
		BlockHash:        p.BlockHash,
		TransactionsRoot: transactionsRoot,
	}, nil
}

func CapellaPayloadToPayloadHeader(p *consensuscapella.ExecutionPayload) (*consensuscapella.ExecutionPayloadHeader, error) {
	if p == nil {
		return nil, fmt.Errorf("nil payload")
	}

	transactions := utilbellatrix.ExecutionPayloadTransactions{Transactions: p.Transactions}
	transactionsRoot, err := transactions.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	withdrawals := utilcapella.ExecutionPayloadWithdrawals{Withdrawals: p.Withdrawals}
	withdrawalsRoot, err := withdrawals.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	return &consensuscapella.ExecutionPayloadHeader{
		ParentHash:       p.ParentHash,
		FeeRecipient:     p.FeeRecipient,
		StateRoot:        p.StateRoot,
		ReceiptsRoot:     p.ReceiptsRoot,
		LogsBloom:        p.LogsBloom,
		PrevRandao:       p.PrevRandao,
		BlockNumber:      p.BlockNumber,
		GasLimit:         p.GasLimit,
		GasUsed:          p.GasUsed,
		Timestamp:        p.Timestamp,
		ExtraData:        p.ExtraData,
		BaseFeePerGas:    p.BaseFeePerGas,
		BlockHash:        p.BlockHash,
		TransactionsRoot: transactionsRoot,
		WithdrawalsRoot:  withdrawalsRoot,
	}, nil
}
