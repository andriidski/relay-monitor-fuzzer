package api

import (
	"github.com/attestantio/go-builder-client/api/bellatrix"
	"github.com/attestantio/go-builder-client/api/capella"
)

type APIConfig struct {
	Host string `yaml:"host"`
	Port uint16 `yaml:"port"`
}

type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type GetHeaderResponseCapella struct {
	Version string                    `json:"version"`
	Data    *capella.SignedBuilderBid `json:"data"`
}

type GetHeaderResponseBellatrix struct {
	Version string                      `json:"version"`
	Data    *bellatrix.SignedBuilderBid `json:"data"`
}
