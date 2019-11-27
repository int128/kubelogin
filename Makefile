TARGET := kubelogin
TARGET_PLUGIN := kubectl-kubelogin
CIRCLE_TAG ?= v1.15.2-pipedrive
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
	VERSION=$(CIRCLE_TAG) goxzst -d dist/gh/ -o "$(TARGET)" -t "kubelogin.rb kubelogin.yaml" -- -ldflags "$(LDFLAGS)"
	mv dist/gh/kubelogin.rb dist/
	mkdir -p dist/plugins
	cp dist/gh/kubelogin.yaml dist/plugins/kubelogin.yaml

.PHONY: release
release: dist
	ghr -u "$(GITHUB_USERNAME)" -r kubelogin "$(CIRCLE_TAG)" dist/gh/
# 	ghcp commit -u "$(CIRCLE_PROJECT_USERNAME)" -r "homebrew-$(CIRCLE_PROJECT_REPONAME)" -m "$(CIRCLE_TAG)" -C dist/ kubelogin.rb
# 	ghcp fork-commit -u kubernetes-sigs -r krew-index -b "oidc-login-$(CIRCLE_TAG)" -m "Bump oidc-login to $(CIRCLE_TAG)" -C dist/ plugins/oidc-login.yaml

.PHONY: clean
clean:
	-rm $(TARGET)
	-rm $(TARGET_PLUGIN)
	-rm -r dist/
