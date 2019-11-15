TARGET := kubelogin
TARGET_PLUGIN := kubectl-oidc_login
CIRCLE_TAG ?= HEAD
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
	-PATH=.:$(PATH) kubectl oidc-login --help

dist:
    # make the zip files for GitHub Releases
	VERSION=$(CIRCLE_TAG) goxzst -d dist/gh/ -i "LICENSE" -o "$(TARGET)" -t "kubelogin.rb oidc-login.yaml" -- -ldflags "$(LDFLAGS)"
	zipinfo dist/gh/kubelogin_linux_amd64.zip
	# make the Homebrew formula
	mv dist/gh/kubelogin.rb dist/
	# make the yaml for krew-index
	mkdir -p dist/plugins
	cp dist/gh/oidc-login.yaml dist/plugins/oidc-login.yaml

.PHONY: release
release: dist
    # publish to the GitHub Releases
	ghr -u "$(CIRCLE_PROJECT_USERNAME)" -r "$(CIRCLE_PROJECT_REPONAME)" "$(CIRCLE_TAG)" dist/gh/
	# publish to the Homebrew tap repository
	ghcp commit -u "$(CIRCLE_PROJECT_USERNAME)" -r "homebrew-$(CIRCLE_PROJECT_REPONAME)" -m "$(CIRCLE_TAG)" -C dist/ kubelogin.rb
	# fork krew-index and create a branch
	ghcp fork-commit -u kubernetes-sigs -r krew-index -b "oidc-login-$(CIRCLE_TAG)" -m "Bump oidc-login to $(CIRCLE_TAG)" -C dist/ plugins/oidc-login.yaml

.PHONY: clean
clean:
	-rm $(TARGET)
	-rm $(TARGET_PLUGIN)
	-rm -r dist/
