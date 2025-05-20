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
	go tool mockery

.PHONY: lint
lint:
	go tool golangci-lint run
