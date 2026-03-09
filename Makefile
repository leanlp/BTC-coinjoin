.PHONY: build test lint vet clean coverage security check all benchmark help

# ═══════════════════════════════════════════════════════════════════════
# RawBlock CoinJoin Forensics Engine — Developer Workflow (Phase 22)
# ═══════════════════════════════════════════════════════════════════════

# Defaults
COVERAGE_THRESHOLD := 25
GO := go
GOLANGCI_LINT := golangci-lint

## build: Compile all packages
build:
	$(GO) build -v ./...

## test: Run all tests with race detection
test:
	$(GO) test -v -race -cover ./...

## test-short: Run tests without verbose output
test-short:
	$(GO) test -race ./...

## benchmark: Run benchmarks with memory profiling
benchmark:
	$(GO) test -bench=. -benchmem -count=1 -run='^$$' ./internal/heuristics/ | tee benchmark.txt
	@echo "✅ Benchmark results saved to benchmark.txt"

## coverage: Generate coverage report and check threshold
coverage:
	$(GO) test -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -func=coverage.out | grep total
	@COVERAGE=$$($(GO) tool cover -func=coverage.out | grep total | awk '{print $$3}' | tr -d '%'); \
	echo "Coverage: $${COVERAGE}%"; \
	if [ $$(echo "$${COVERAGE} < $(COVERAGE_THRESHOLD)" | bc -l) -eq 1 ]; then \
		echo "❌ Coverage below $(COVERAGE_THRESHOLD)% threshold"; \
		exit 1; \
	fi; \
	echo "✅ Coverage meets $(COVERAGE_THRESHOLD)% threshold"

## coverage-html: Open coverage report in browser
coverage-html: coverage
	$(GO) tool cover -html=coverage.out -o coverage.html
	open coverage.html

## lint: Run golangci-lint
lint:
	$(GOLANGCI_LINT) run --timeout=5m ./...

## vet: Run go vet
vet:
	$(GO) vet ./...

## security: Run govulncheck for vulnerabilities
security:
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

## stats: Show engine statistics
stats:
	@echo "═══════════════════════════════════════════"
	@echo "  RawBlock Forensics Engine Stats"
	@echo "═══════════════════════════════════════════"
	@echo "Go files:      $$(find internal/heuristics -name '*.go' -not -name '*_test.go' | wc -l | tr -d ' ')"
	@echo "Lines of code: $$(wc -l internal/heuristics/*.go 2>/dev/null | tail -1 | awk '{print $$1}')"
	@echo "Test files:    $$(find internal/heuristics -name '*_test.go' | wc -l | tr -d ' ')"
	@echo "Pipeline steps:$$(grep -c 'STEP [0-9]' internal/heuristics/ssmp.go || echo 0)"
	@echo "Flag bits:     $$(grep -c 'Flag[A-Z].*= 1 <<' internal/heuristics/llr_engine.go || echo 0)"
	@echo "═══════════════════════════════════════════"

## check: Run all checks (build + test + lint + vet)
check: build test lint vet
	@echo "✅ All checks passed"

## clean: Remove build artifacts
clean:
	rm -f coverage.out coverage.html benchmark.txt
	$(GO) clean -cache

## all: Full CI pipeline locally
all: clean check coverage security stats
	@echo "🎯 Full pipeline completed successfully"

## help: Show available commands
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
