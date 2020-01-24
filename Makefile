# CI must provide the following variables (on tag push)
# VERSION
# GITHUB_USERNAME
# GITHUB_REPONAME

TARGET := kubelogin
VERSION ?= latest
LDFLAGS := -X main.version=$(VERSION)

all: $(TARGET)

$(TARGET): $(wildcard *.go)
	go build -o $@ -ldflags "$(LDFLAGS)"

.PHONY: ci
ci:
	$(MAKE) check
	bash -c "bash <(curl -s https://codecov.io/bash)"
	$(MAKE) dist

.PHONY: check
check:
	golangci-lint run
	go test -v -race -cover -coverprofile=coverage.out ./... > gotest.log

.PHONY: dist
dist: dist/output
dist/output:
	# make the zip files for GitHub Releases
	VERSION=$(VERSION) CGO_ENABLED=0 goxzst -d dist/output -i "LICENSE" -o "$(TARGET)" -t "dist/kubelogin.rb dist/oidc-login.yaml dist/Dockerfile" -- -ldflags "$(LDFLAGS)"
	# test the zip file
	zipinfo dist/output/kubelogin_linux_amd64.zip
	# make the krew yaml structure
	mkdir -p dist/output/plugins
	mv dist/output/oidc-login.yaml dist/output/plugins/oidc-login.yaml

.PHONY: release
release: dist
	# publish to the GitHub Releases
	ghr -u "$(GITHUB_USERNAME)" -r "$(GITHUB_REPONAME)" "$(VERSION)" dist/output/
	# publish to the Homebrew tap repository
	ghcp commit -u "$(GITHUB_USERNAME)" -r "homebrew-$(GITHUB_REPONAME)" -m "$(VERSION)" -C dist/output/ kubelogin.rb
	# publish the Dockerfile
	ghcp commit -u "$(GITHUB_USERNAME)" -r "$(GITHUB_REPONAME)-docker" -b "bump-$(VERSION)" -m "Bump the version to $(VERSION)" -C dist/output/ Dockerfile
	ghcp pull-request -u "$(GITHUB_USERNAME)" -r "$(GITHUB_REPONAME)-docker" -b "bump-$(VERSION)" --title "Bump the version to $(VERSION)"
	# fork krew-index and create a branch
	ghcp fork-commit -u kubernetes-sigs -r krew-index -b "oidc-login-$(VERSION)" -m "Bump oidc-login to $(VERSION)" -C dist/output/ plugins/oidc-login.yaml

.PHONY: clean
clean:
	-rm $(TARGET)
	-rm -r dist/output/
	-rm coverage.out gotest.log

.PHONY: ci-setup-linux-amd64
ci-setup-linux-amd64:
	mkdir -p ~/bin
	# https://github.com/golangci/golangci-lint
	curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b ~/bin v1.21.0
	# https://github.com/int128/goxzst
	curl -sfL -o /tmp/goxzst.zip https://github.com/int128/goxzst/releases/download/v0.3.0/goxzst_linux_amd64.zip
	unzip /tmp/goxzst.zip -d ~/bin
	# https://github.com/int128/ghcp
	curl -sfL -o /tmp/ghcp.zip https://github.com/int128/ghcp/releases/download/v1.8.0/ghcp_linux_amd64.zip
	unzip /tmp/ghcp.zip -d ~/bin
	# https://github.com/tcnksm/ghr
	curl -sfL -o /tmp/ghr.tgz https://github.com/tcnksm/ghr/releases/download/v0.13.0/ghr_v0.13.0_linux_amd64.tar.gz
	tar -xf /tmp/ghr.tgz -C ~/bin --strip-components 1 --wildcards "*/ghr"
