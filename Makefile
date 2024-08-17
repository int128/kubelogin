.PHONY: all
all:

.PHONY: generate
generate:
	$(MAKE) -C tools
	rm -fr mocks/
	./tools/bin/mockery
