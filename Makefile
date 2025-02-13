.PHONY: all
all:

.PHONY: test
test:
	go test -v -race ./pkg/...

.PHONY: integration-test
integration-test:
	go test -v -race ./integration_test/...

.PHONY: generate
generate:
	go tool github.com/google/wire/cmd/wire ./pkg/di
	rm -fr mocks/
	go tool github.com/vektra/mockery/v2

.PHONY: lint
lint:
	go tool github.com/golangci/golangci-lint/cmd/golangci-lint run
