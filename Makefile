## jensec Â· vigyl â€” Makefile
## Usage: make <target>

BINARY     := jensec
MODULE     := github.com/isthobbit/vigyl
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS    := -ldflags "-X $(MODULE)/pkg/version.Version=$(VERSION) \
                         -X $(MODULE)/pkg/version.Commit=$(COMMIT) \
                         -X $(MODULE)/pkg/version.BuildDate=$(BUILD_DATE)"

.PHONY: all build clean test lint scan install help

all: build

## build: compile the jensec binary into ./bin/
build:
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/jensec
	@echo "Built bin/$(BINARY) ($(VERSION))"

## install: install jensec to $GOPATH/bin
install:
	go install $(LDFLAGS) ./cmd/jensec
	@echo "Installed $(BINARY)"

## test: run all tests
test:
	go test ./... -v -timeout 60s

## lint: run go vet
lint:
	go vet ./...

## scan: run jensec against itself (dogfood)
scan: build
	./bin/$(BINARY) scan all . --fail-on high

## scan-secrets: secrets scan only
scan-secrets: build
	./bin/$(BINARY) scan secrets . --fail-on high

## scan-sast: SAST scan only
scan-sast: build
	./bin/$(BINARY) scan sast . --fail-on high

## clean: remove build artifacts
clean:
	rm -rf bin/
	rm -f secrets-report.json sast-report.json

## help: show this help
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
