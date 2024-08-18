GOBIN := $(CURDIR)/bin
export GOBIN

all: bin/mockery bin/wire

bin/mockery:
	go install github.com/vektra/mockery/v2

bin/wire:
	go install github.com/google/wire/cmd/wire
