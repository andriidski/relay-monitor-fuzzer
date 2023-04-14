package main

import (
	"context"
	"flag"
	"log"
	"os"

	fuzzer "github.com/andriidski/rm-builder-fuzzer/pkg/fuzzer"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"
)

var configFile = flag.String("config", "config.example.yaml", "path to config file")

func main() {
	flag.Parse()

	loggingConfig := zap.NewDevelopmentConfig()
	loggingConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	zapLogger, err := loggingConfig.Build()
	if err != nil {
		log.Fatalf("could not open log file: %v", err)
	}
	defer func() {
		err := zapLogger.Sync()
		if err != nil {
			log.Fatalf("could not flush log: %v", err)
		}
	}()

	logger := zapLogger.Sugar()

	data, err := os.ReadFile(*configFile)
	if err != nil {
		logger.Fatalf("could not read config file: %v", err)
	}

	config := &fuzzer.Config{}
	err = yaml.Unmarshal(data, config)
	if err != nil {
		logger.Fatalf("could not load config: %v", err)
	}
	logger.Infof("fuzzing builder bid fault config: %v", config.Fuzzer.BuilderBidFaultConfig.String())
	logger.Infow("fuzzing network config", "network", config.Network.String())

	ctx := context.Background()
	logger.Infof("starting builder fuzzer for %s network", config.Network.Name)
	fuzz, err := fuzzer.New(ctx, config, zapLogger)
	if err != nil {
		logger.Fatalf("could not start builder fuzzer: %v", err)
	}
	fuzz.Run(ctx)
}
