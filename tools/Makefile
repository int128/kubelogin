GOBIN := $(CURDIR)/bin
export GOBIN

all: bin/mockery bin/wire bin/golangci-lint

bin/mockery:
	go install github.com/vektra/mockery/v2

bin/wire:
	go install github.com/google/wire/cmd/wire

bin/golangci-lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint
