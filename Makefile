TARGET := kubelogin
OSARCH := darwin/amd64 linux/amd64 windows/amd64

.PHONY: check release_bin release_homebrew release clean

all: $(TARGET)

check:
	golint
	go vet
	$(MAKE) -C adaptors_test/authserver/testdata
	go test -v ./...

$(TARGET): check
	go build -o $@

dist/bin: check
	gox --osarch '$(OSARCH)' -output 'dist/bin/$(TARGET)_{{.OS}}_{{.Arch}}'

release_bin: dist/bin
	ghr -u "$(CIRCLE_PROJECT_USERNAME)" -r "$(CIRCLE_PROJECT_REPONAME)" -b "$$(ghch -F markdown --latest)" "$(CIRCLE_TAG)" dist/bin

dist/kubelogin.rb: dist/bin
	./homebrew.sh dist/bin/$(TARGET)_darwin_amd64 > dist/kubelogin.rb

release_homebrew: dist/kubelogin.rb
	ghcp -u "$(CIRCLE_PROJECT_USERNAME)" -r "homebrew-$(CIRCLE_PROJECT_REPONAME)" -m "$(CIRCLE_TAG)" -C dist/ kubelogin.rb

release: release_bin release_homebrew

clean:
	-rm "$(TARGET)"
	-rm -r dist/
