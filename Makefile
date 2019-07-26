TARGET := kubelogin
TARGET_PLUGIN := kubectl-oidc_login
CIRCLE_TAG ?= HEAD
LDFLAGS := -X main.version=$(CIRCLE_TAG)

.PHONY: check run diagram release clean

all: $(TARGET)

check:
	golangci-lint run
	$(MAKE) -C e2e_test/keys/testdata
	go test -v -race -cover -coverprofile=coverage.out ./...

$(TARGET): $(wildcard *.go)
	go build -o $@ -ldflags "$(LDFLAGS)"

$(TARGET_PLUGIN): $(TARGET)
	ln -sf $(TARGET) $@

run: $(TARGET_PLUGIN)
	-PATH=.:$(PATH) kubectl oidc-login --help

diagram: docs/authn.png

%.png: %.seqdiag
	seqdiag -a -f /Library/Fonts/Verdana.ttf $<

dist:
	VERSION=$(CIRCLE_TAG) goxzst -d dist/gh/ -o "$(TARGET)" -t "kubelogin.rb oidc-login.yaml" -- -ldflags "$(LDFLAGS)"
	mv dist/gh/kubelogin.rb dist/
	mkdir -p dist/plugins
	cp dist/gh/oidc-login.yaml dist/plugins/oidc-login.yaml

release: dist
	ghr -u "$(CIRCLE_PROJECT_USERNAME)" -r "$(CIRCLE_PROJECT_REPONAME)" "$(CIRCLE_TAG)" dist/gh/
	ghcp commit -u "$(CIRCLE_PROJECT_USERNAME)" -r "homebrew-$(CIRCLE_PROJECT_REPONAME)" -m "$(CIRCLE_TAG)" -C dist/ kubelogin.rb
	ghcp fork-commit -u kubernetes-sigs -r krew-index -b "oidc-login-$(CIRCLE_TAG)" -m "Bump oidc-login to $(CIRCLE_TAG)" -C dist/ plugins/oidc-login.yaml

clean:
	-rm $(TARGET)
	-rm $(TARGET_PLUGIN)
	-rm -r dist/
