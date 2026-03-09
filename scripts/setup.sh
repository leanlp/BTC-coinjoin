#!/bin/sh
# Setup script: installs pre-commit hook and development tools
set -e

echo "🔧 Setting up development environment..."

# Install pre-commit hook
echo "  → Installing pre-commit hook..."
cp scripts/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
echo "  ✅ Pre-commit hook installed"

# Install golangci-lint if not present
if ! command -v golangci-lint &> /dev/null; then
    echo "  → Installing golangci-lint..."
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.5
    echo "  ✅ golangci-lint installed"
else
    echo "  ✅ golangci-lint already installed"
fi

# Install govulncheck if not present
if ! command -v govulncheck &> /dev/null; then
    echo "  → Installing govulncheck..."
    go install golang.org/x/vuln/cmd/govulncheck@latest
    echo "  ✅ govulncheck installed"
else
    echo "  ✅ govulncheck already installed"
fi

# Verify dependencies
echo "  → Verifying Go modules..."
go mod verify

echo ""
echo "✅ Development environment ready!"
echo ""
echo "Available commands:"
echo "  make build     — Compile all packages"
echo "  make test      — Run tests with race detection"
echo "  make lint      — Run golangci-lint"
echo "  make coverage  — Check coverage threshold"
echo "  make check     — Run all checks"
echo "  make all       — Full CI pipeline locally"
