package fuzzer

import (
	"context"
	"errors"
	"fmt"

	"github.com/andriidski/relay-monitor-fuzzer/pkg/api"
	"github.com/andriidski/relay-monitor-fuzzer/pkg/builder"
	"github.com/andriidski/relay-monitor-fuzzer/pkg/consensus"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/bls"
	"go.uber.org/zap"
)

type Fuzzer struct {
	logger *zap.Logger

	api     *api.API
	builder *builder.Builder
}

func New(ctx context.Context, config *Config, zapLogger *zap.Logger) (*Fuzzer, error) {
	logger := zapLogger.Sugar()

	// Instantiate the block builder.
	envBuilderSkBytes, err := hexutil.Decode(config.Builder.SecretKey)
	if err != nil {
		return nil, errors.New("incorrect builder API secret key provided")
	}

	var dataVersion spec.DataVersion
	if config.Network.Version == "bellatrix" {
		dataVersion = spec.DataVersionBellatrix
	} else if config.Network.Version == "capella" {
		dataVersion = spec.DataVersionCapella
	} else {
		logger.Fatal("invalid version: %s", config.Network.Version)
	}

	builderSk, err := bls.SecretKeyFromBytes(envBuilderSkBytes[:])
	if err != nil {
		return nil, errors.New("incorrect builder API secret key provided")
	}

	// Instantiate the consensus client.
	consensusClient, err := consensus.NewClient(ctx, config.Consensus.Endpoint, zapLogger)
	if err != nil {
		return nil, fmt.Errorf("could not instantiate consensus client: %v", err)
	}
	// Get a clock instance.
	clock := consensus.NewClock(consensusClient.GenesisTime, consensusClient.SecondsPerSlot, consensusClient.SlotsPerEpoch)

	// Instantiate a mocked block builder. This is used to create bids with
	// faults determined by the configuration.
	builder := builder.New(&config.Fuzzer.BuilderBidFaultConfig, consensusClient, clock, builderSk, consensusClient.SignatureDomainForBuilder(), logger)

	// Instantiate the API server.
	apiServer := api.New(config.API, dataVersion, zapLogger, builder)

	return &Fuzzer{
		logger:  zapLogger,
		api:     apiServer,
		builder: builder,
	}, nil
}

func (fuzzer *Fuzzer) Run(ctx context.Context) {
	logger := fuzzer.logger.Sugar()

	err := fuzzer.api.Run(ctx)
	println("API server stopped")
	if err != nil {
		logger.Warn("error running API server: %v", err)
	}
}
