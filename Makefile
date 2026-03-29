BINARY   := tlspeek
DIST     := dist
SRC      := tlspeek.go
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -s -w -X main.version=$(VERSION)

PLATFORMS := \
	darwin/amd64  \
	darwin/arm64  \
	linux/amd64   \
	linux/arm64   \
	windows/amd64 \
	windows/arm64

.PHONY: all build checksum clean

all: build checksum

build:
	@mkdir -p $(DIST)
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*}; \
		GOARCH=$${platform#*/}; \
		output=$(DIST)/$(BINARY)-$${GOOS}-$${GOARCH}; \
		if [ "$$GOOS" = "windows" ]; then output=$${output}.exe; fi; \
		echo "Building $$output ..."; \
		CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH go build -trimpath -ldflags="$(LDFLAGS)" -o $$output $(SRC); \
	done

checksum:
	@cd $(DIST) && shasum -a 256 $(BINARY)-* > sha256sums.txt
	@echo "Checksums written to $(DIST)/sha256sums.txt"
	@cat $(DIST)/sha256sums.txt

clean:
	rm -rf $(DIST)
