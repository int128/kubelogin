PRODUCT := kubelogin
TARGET_ARCHIVE := $(PRODUCT)_$(GOOS)_$(GOARCH).zip
TARGET_DIGEST := $(PRODUCT)_$(GOOS)_$(GOARCH).zip.sha256

ifeq ($(GOOS), windows)
  TARGET := $(PRODUCT).exe
else
  TARGET := $(PRODUCT)
endif

# determine the version from ref
ifeq ($(GITHUB_REF), refs/heads/master)
  VERSION := latest
else
  VERSION ?= $(notdir $(GITHUB_REF))
endif

LDFLAGS := -X main.version=$(VERSION)

all: $(TARGET)

$(TARGET):
	go build -o $@ -ldflags "$(LDFLAGS)"

.PHONY: dist
dist: $(TARGET_ARCHIVE) $(TARGET_DIGEST)
$(TARGET_ARCHIVE): $(TARGET)
ifeq ($(GOOS), windows)
	powershell Compress-Archive -Path $(TARGET),LICENSE,README.md -DestinationPath $@
else
	zip $@ $(TARGET) LICENSE README.md
endif

$(TARGET_DIGEST): $(TARGET_ARCHIVE)
ifeq ($(GOOS), darwin)
	shasum -a 256 -b $(TARGET_ARCHIVE) > $@
else
	sha256sum -b $(TARGET_ARCHIVE) > $@
endif

.PHONY: dist-release
dist-release: dist
	gh release upload $(VERSION) $(TARGET_ARCHIVE) $(TARGET_DIGEST) --clobber

.PHONY: clean
clean:
	-rm $(TARGET)
	-rm -r dist/output/
	-rm coverage.out gotest.log
