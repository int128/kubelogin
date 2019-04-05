TARGET := kubelogin
TARGET_PLUGIN := kubectl-oidc_login
CIRCLE_TAG ?= HEAD
LDFLAGS := -X main.version=$(CIRCLE_TAG)

.PHONY: check run release clean

all: $(TARGET)

check:
	golint
	go vet
	$(MAKE) -C adaptors_test/authserver/testdata
	go test -v ./...

$(TARGET): $(wildcard *.go)
	go build -o $@ -ldflags "$(LDFLAGS)"

$(TARGET_PLUGIN): $(TARGET)
	ln -sf $(TARGET) $@

run: $(TARGET_PLUGIN)
	-PATH=.:$(PATH) kubectl oidc-login --help

dist:
	VERSION=$(CIRCLE_TAG) goxzst -d dist/gh/ -o "$(TARGET)" -t "kubelogin.rb oidc-login.yaml" -- -ldflags "$(LDFLAGS)"
	mv dist/gh/kubelogin.rb dist/

release: dist
	ghr -u "$(CIRCLE_PROJECT_USERNAME)" -r "$(CIRCLE_PROJECT_REPONAME)" "$(CIRCLE_TAG)" dist/gh/
	ghcp -u "$(CIRCLE_PROJECT_USERNAME)" -r "homebrew-$(CIRCLE_PROJECT_REPONAME)" -m "$(CIRCLE_TAG)" -C dist/ kubelogin.rb

clean:
	-rm $(TARGET)
	-rm $(TARGET_PLUGIN)
	-rm -r dist/
