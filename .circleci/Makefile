.PHONY: all
all:

.PHONY: install-test-deps
install-test-deps:
	go get -v github.com/int128/goxzst

.PHONY: install-release-deps
install-release-deps: go
	go get -v github.com/int128/goxzst github.com/int128/ghcp

go:
	curl -sSfL -o go.tgz "https://golang.org/dl/go`ruby go_version_from_config.rb < config.yml`.darwin-amd64.tar.gz"
	tar -xf go.tgz
	rm go.tgz
	./go/bin/go version
