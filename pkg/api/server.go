package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/andriidski/relay-monitor-fuzzer/pkg/builder"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

const (
	methodNotSupported = "method not supported"

	GetHeaderEndpoint = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	GetStatusEndpoint = "/eth/v1/builder/status"
)

type API struct {
	config *APIConfig
	logger *zap.SugaredLogger

	builder *builder.Builder

	version spec.DataVersion
}

func New(config *APIConfig, version spec.DataVersion, logger *zap.Logger, builder *builder.Builder) *API {
	return &API{
		config:  config,
		logger:  logger.Sugar(),
		builder: builder,
		version: version,
	}
}

func (api *API) respondError(w http.ResponseWriter, code int, message string) {

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	response := APIError{code, message}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")

	if err := encoder.Encode(response); err != nil {
		api.logger.Errorw("couldn't write error response", "response", response, "error", err)
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (api *API) respondOK(w http.ResponseWriter, response any) {

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		api.logger.Errorw("couldn't write OK response", "response", response, "error", err)
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (api *API) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	slotStr := vars["slot"]
	parentHashHex := vars["parent_hash"]
	proposerPubkeyHex := vars["pubkey"]

	slot, err := strconv.ParseUint(slotStr, 10, 64)
	if err != nil {
		api.respondError(w, http.StatusBadRequest, "invalid slot")
		return
	}

	if len(proposerPubkeyHex) != 98 {
		api.respondError(w, http.StatusBadRequest, "invalid pubkey")
		return
	}

	if len(parentHashHex) != 66 {
		api.respondError(w, http.StatusBadRequest, "invalid parent hash")
		return
	}

	signedBuilderBid, err := api.builder.GetSignedBuilderBid(api.version, slot, parentHashHex, proposerPubkeyHex)
	if err != nil {
		api.respondError(w, http.StatusInternalServerError, "error getting header")
		return
	}
	switch api.version {
	case spec.DataVersionBellatrix:
		api.logger.Infof("sending signed builder bid: %+v", signedBuilderBid.Bellatrix)
		api.respondOK(w, &GetHeaderResponseBellatrix{
			Version: api.version.String(),
			Data:    signedBuilderBid.Bellatrix,
		})
	case spec.DataVersionCapella:
		api.logger.Infof("sending signed builder bid: %+v", signedBuilderBid.Capella)
		api.respondOK(w, &GetHeaderResponseCapella{
			Version: api.version.String(),
			Data:    signedBuilderBid.Capella,
		})
	default:
		api.respondError(w, http.StatusInternalServerError, "unknown data version")
	}
}

func (api *API) handleGetStatus(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (api *API) Run(ctx context.Context) error {
	host := fmt.Sprintf("%s:%d", api.config.Host, api.config.Port)
	api.logger.Infof("API server listening on %s", host)

	r := mux.NewRouter()

	// API implements two endpoints:
	// 1. getHeader() -> returns a signed builder bid
	// 2. getStatus() -> returns the status of the builder/relay
	r.HandleFunc(GetHeaderEndpoint, get(api.handleGetHeader))
	r.HandleFunc(GetStatusEndpoint, get(api.handleGetStatus))

	return http.ListenAndServe(host, r)
}

func get(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			handler(w, r)
		default:
			w.WriteHeader(404)
			n, err := w.Write([]byte(methodNotSupported))
			if n != len(methodNotSupported) {
				http.Error(w, "error writing message", http.StatusInternalServerError)
				return
			}
			if err != nil {
				http.Error(w, "error writing message", http.StatusInternalServerError)
				return
			}
		}
	}
}
