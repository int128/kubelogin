# CircleCI specific variables
CIRCLE_TAG ?= latest
GITHUB_USERNAME := $(CIRCLE_PROJECT_USERNAME)
GITHUB_REPONAME := $(CIRCLE_PROJECT_REPONAME)

TARGET := kubelogin
TARGET_OSARCH := linux_amd64 darwin_amd64 windows_amd64 linux_arm linux_arm64
VERSION ?= $(CIRCLE_TAG)
LDFLAGS := -X main.version=$(VERSION)

all: $(TARGET)

$(TARGET): $(wildcard **/*.go)
	go build -o $@ -ldflags "$(LDFLAGS)"

.PHONY: dist
dist: dist/output
dist/output:
	# make the zip files for GitHub Releases
	VERSION=$(VERSION) goxzst -d dist/output -i "LICENSE" -o "$(TARGET)" -osarch "$(TARGET_OSARCH)" -t "dist/kubelogin.rb dist/oidc-login.yaml dist/Dockerfile" -- -ldflags "$(LDFLAGS)"
	# test the zip file
	zipinfo dist/output/kubelogin_linux_amd64.zip
	# make the krew yaml structure
	mkdir -p dist/output/plugins
	mv dist/output/oidc-login.yaml dist/output/plugins/oidc-login.yaml

.PHONY: release
release: dist
	# publish the binaries
	ghcp release -u "$(GITHUB_USERNAME)" -r "$(GITHUB_REPONAME)" -t "$(VERSION)" dist/output/
	# publish the Homebrew formula
	ghcp commit -u "$(GITHUB_USERNAME)" -r "homebrew-$(GITHUB_REPONAME)" -b "bump-$(VERSION)" -m "Bump the version to $(VERSION)" -C dist/output/ kubelogin.rb
	ghcp pull-request -u "$(GITHUB_USERNAME)" -r "homebrew-$(GITHUB_REPONAME)" -b "bump-$(VERSION)" --title "Bump the version to $(VERSION)"
	# publish the Dockerfile
	ghcp commit -u "$(GITHUB_USERNAME)" -r "$(GITHUB_REPONAME)-docker" -b "bump-$(VERSION)" -m "Bump the version to $(VERSION)" -C dist/output/ Dockerfile
	ghcp pull-request -u "$(GITHUB_USERNAME)" -r "$(GITHUB_REPONAME)-docker" -b "bump-$(VERSION)" --title "Bump the version to $(VERSION)"
	# publish the Krew manifest
	ghcp fork-commit -u kubernetes-sigs -r krew-index -b "oidc-login-$(VERSION)" -m "Bump oidc-login to $(VERSION)" -C dist/output/ plugins/oidc-login.yaml

.PHONY: clean
clean:
	-rm $(TARGET)
	-rm -r dist/output/
	-rm coverage.out gotest.log
