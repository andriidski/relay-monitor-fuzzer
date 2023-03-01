VERSION ?= $(shell git describe --tags --always --dirty="-dev")

all: clean build

v:
	@echo "Version: ${VERSION}"

clean:
	git clean -fdx

build:
	go build -ldflags "-X cmd.Version=${VERSION} -X main.Version=${VERSION}" -v -o builder-fuzzer .

test:
	go test ./...

test-race:
	go test -race ./...
