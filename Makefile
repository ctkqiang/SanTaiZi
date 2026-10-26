# SanTaiZi build and install helpers.
#
# The default module path in go.mod is "santaizi", so run these targets from a
# repository checkout. `make install` uses `go install` with GOBIN pointing at
# modules/bin so the framework loader can discover the binaries. Use
# `make install-global` for a normal standalone install into GOBIN/GOPATH/bin.

GO          ?= go
LINT        ?= golangci-lint
MODULE_DIR  := modules
MODULES     := php2shell vecmap wifisec cve_2025_14847
BIN_DIR     := $(CURDIR)/modules/bin

.PHONY: all build install install-global install-all test vet lint santaizi framework clean help

all: build

build:
	@mkdir -p "$(BIN_DIR)"
	@for module in $(MODULES); do \
		echo "==> build $$module"; \
		( cd "$(MODULE_DIR)/$$module" && $(GO) build -o "$(BIN_DIR)/$$module" . ) || exit 1; \
	done
	@echo "Binaries: $(BIN_DIR)"

install:
	@mkdir -p "$(BIN_DIR)"
	@for module in $(MODULES); do \
		echo "==> go install $$module"; \
		GOBIN="$(BIN_DIR)" $(GO) install "./$(MODULE_DIR)/$$module" || exit 1; \
	done
	@echo "Installed to $(BIN_DIR)"
	@echo "Run the framework with: export SANTAIZI_MODULES_DIR=$(CURDIR)/modules"

install-global:
	@for module in $(MODULES); do \
		echo "==> go install $$module"; \
		$(GO) install "./$(MODULE_DIR)/$$module" || exit 1; \
	done
	@bin="$$($(GO) env GOBIN)"; [ -n "$$bin" ] || bin="$$($(GO) env GOPATH)/bin"; echo "Installed to $$bin"

install-all:
	@mkdir -p "$(BIN_DIR)"
	GOBIN="$(BIN_DIR)" $(GO) install "./$(MODULE_DIR)/..."

test:
	$(GO) test ./...

vet:
	$(GO) vet ./framework ./internal/structure ./sdk ./modules/...

lint:
	$(LINT) run ./framework ./internal/structure ./sdk ./modules/php2shell ./modules/vecmap ./modules/wifisec ./modules/cve_2025_14847

santaizi:
	$(GO) build -o "$(CURDIR)/santaizi" ./framework

framework:
	$(GO) build -o "$(BIN_DIR)/santaizi" ./framework

clean:
	@for module in $(MODULES); do rm -f "$(BIN_DIR)/$$module"; done

help:
	@printf '%s\n' \
		'SanTaiZi targets:' \
		'  make build           build the four modules into modules/bin' \
		'  make install         go install into modules/bin (framework loader)' \
		'  make install-global  go install into GOBIN/GOPATH/bin (standalone)' \
		'  make install-all     go install every module under modules/' \
		'  make santaizi        build the console to ./santaizi' \
		'  make framework       build the console to modules/bin/santaizi' \
		'  make test vet lint   run verification' \
		'  make clean           remove the four module binaries from modules/bin'
