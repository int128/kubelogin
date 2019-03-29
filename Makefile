TARGET := kubelogin
OSARCH := darwin/amd64 linux/amd64 windows/amd64
CIRCLE_TAG ?= snapshot

.PHONY: check release_bin release_homebrew release clean

all: dist/$(TARGET)

check:
	golint
	go vet
	$(MAKE) -C cli_test/authserver/testdata
	go test -v ./...

dist/$(TARGET): $(wildcard *.go)
	go build -o $@ -ldflags '-X main.version=$(CIRCLE_TAG)'

dist/bin:
	gox --osarch '$(OSARCH)' -output 'dist/bin/$(TARGET)_{{.OS}}_{{.Arch}}'
	cd dist/bin && shasum -a 256 -b * > $(TARGET)_checksums.txt

release_bin: dist/bin
	ghr -u "$(CIRCLE_PROJECT_USERNAME)" -r "$(CIRCLE_PROJECT_REPONAME)" -b "$$(ghch -F markdown --latest)" "$(CIRCLE_TAG)" dist/bin

dist/kubelogin.rb: dist/bin
	./homebrew.sh dist/bin/$(TARGET)_darwin_amd64 > dist/kubelogin.rb

release_homebrew: dist/kubelogin.rb
	ghcp -u "$(CIRCLE_PROJECT_USERNAME)" -r "homebrew-$(CIRCLE_PROJECT_REPONAME)" -m "$(CIRCLE_TAG)" -C dist/ kubelogin.rb

release: release_bin release_homebrew

clean:
	-rm -r dist/
