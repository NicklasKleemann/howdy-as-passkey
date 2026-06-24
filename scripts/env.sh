# Source this (`. scripts/env.sh`) to scope all Go + Python work to the project.
# Keeps module cache, build cache, installed binaries and the Python venv inside
# the repo — nothing leaks to ~/go or system site-packages.

HPB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
export HPB_ROOT

# Go: project-local everything
export GOPATH="$HPB_ROOT/.go"
export GOMODCACHE="$HPB_ROOT/.go/pkg/mod"
export GOCACHE="$HPB_ROOT/.go/cache"
export GOBIN="$HPB_ROOT/bin"
export GOFLAGS="-mod=vendor"          # build from vendored deps, reproducible/offline
export PATH="$GOBIN:$PATH"

# Python: project-local venv (uv)
if [ -f "$HPB_ROOT/.venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    . "$HPB_ROOT/.venv/bin/activate"
fi

echo "env scoped to $HPB_ROOT (GOPATH=$GOPATH, venv=$([ -n "${VIRTUAL_ENV:-}" ] && echo on || echo off))"
