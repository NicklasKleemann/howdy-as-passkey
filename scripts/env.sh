# Source this (`. scripts/env.sh`) to scope all Go work to the project.
# Keeps the module cache, build cache, and installed binaries inside the repo -
# nothing leaks to ~/go.

HPB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
export HPB_ROOT

# Go: project-local everything
export GOPATH="$HPB_ROOT/.go"
export GOMODCACHE="$HPB_ROOT/.go/pkg/mod"
export GOCACHE="$HPB_ROOT/.go/cache"
export GOBIN="$HPB_ROOT/bin"
export GOFLAGS="-mod=vendor"          # build from vendored deps, reproducible/offline
export PATH="$GOBIN:$PATH"

echo "env scoped to $HPB_ROOT (GOPATH=$GOPATH)"
