TARGET := kubelogin
TARGET_PLUGIN := kubectl-kubelogin
CIRCLE_TAG ?= v1.16.1-pipedrive
LDFLAGS := -X main.version=$(CIRCLE_TAG)

all: $(TARGET)

.PHONY: check
check:
	golangci-lint run
	go test -v -race -cover -coverprofile=coverage.out ./...

$(TARGET): $(wildcard *.go)
	go build -o $@ -ldflags "$(LDFLAGS)"

$(TARGET_PLUGIN): $(TARGET)
	ln -sf $(TARGET) $@

.PHONY: run
run: $(TARGET_PLUGIN)
	-PATH=.:$(PATH) kubectl kubelogin --help

dist:
	VERSION=$(CIRCLE_TAG) goxzst -d dist/gh/ -o "$(TARGET)" -osarch "linux_amd64 darwin_amd64 darwin_arm64 windows_amd64" -t "kubelogin.rb kubelogin.yaml" -- -ldflags "$(LDFLAGS)"
	mv dist/gh/kubelogin.rb dist/
	mkdir -p dist/plugins
	cp dist/gh/kubelogin.yaml dist/plugins/kubelogin.yaml

.PHONY: release
release: dist
	gh release --repo pipedrive/kubelogin create "$(CIRCLE_TAG)" dist/gh/*

.PHONY: clean
clean:
	-rm $(TARGET)
	-rm $(TARGET_PLUGIN)
	-rm -r dist/
