.PHONY: all
all:

.PHONY: test
test:
	go test -v -race ./pkg/...

.PHONY: integration-test
integration-test:
	go go test -v -race ./integration_test/...

.PHONY: generate
generate:
	$(MAKE) -C tools
	./tools/bin/wire ./pkg/di
	rm -fr mocks/
	./tools/bin/mockery

.PHONY: lint
lint:
	$(MAKE) -C tools
	./tools/bin/golangci-lint run
