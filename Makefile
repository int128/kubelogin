.PHONY: all
all:

.PHONY: generate
generate:
	$(MAKE) -C tools
	./tools/bin/wire ./pkg/di
	rm -fr mocks/
	./tools/bin/mockery
