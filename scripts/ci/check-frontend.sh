#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
vite_plus_image='ghcr.io/voidzero-dev/vite-plus:1.4.0@sha256:5dfa2031f7d014b6376407fd99e0747bed329d792c79c184a65ec9a0765bee0e'

ephemeral_store=false
if [ -n "${PNPM_STORE_DIR:-}" ]; then
    pnpm_store="$PNPM_STORE_DIR"
elif [ -n "${npm_config_cache:-}" ] && [ -d "$npm_config_cache" ] && [ -w "$npm_config_cache" ]; then
    pnpm_store="$npm_config_cache/pnpm-store"
elif [ -d /var/lib/jenkins/.cache/fleet-packages/npm ] && [ -w /var/lib/jenkins/.cache/fleet-packages/npm ]; then
    pnpm_store="/var/lib/jenkins/.cache/fleet-packages/npm/pnpm-store"
else
    pnpm_store="$(mktemp -d "${TMPDIR:-/tmp}/pocket-id-pnpm-store.XXXXXX")"
    ephemeral_store=true
fi

cleanup() {
    if [ "$ephemeral_store" = true ]; then
        rm -rf "$pnpm_store"
    fi
}
trap cleanup EXIT

mkdir -p "$pnpm_store"

docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e CI=true \
    -e PNPM_STORE_DIR=/cache/pnpm-store \
    -e npm_config_store_dir=/cache/pnpm-store \
    -v "$root:/src:ro" \
    -v "$pnpm_store:/cache/pnpm-store" \
    "$vite_plus_image" \
    sh -eu -c '
        work="$(mktemp -d)"
        trap "rm -rf \"$work\"" EXIT
        export HOME="$work/home"
        export XDG_CACHE_HOME="$work/cache"
        export XDG_CONFIG_HOME="$work/config"
        export XDG_DATA_HOME="$work/data"
        mkdir -p "$HOME" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$work/frontend" "$work/tests" "$work/email-templates"
        cp /src/package.json /src/pnpm-workspace.yaml /src/pnpm-lock.yaml /src/.node-version "$work/"
        cp /src/tests/package.json "$work/tests/"
        cp /src/email-templates/package.json "$work/email-templates/"
        cp -r /src/frontend/. "$work/frontend/"
        cd "$work"
        vp -C frontend install --frozen-lockfile
        vp -C frontend run build
        vp -C frontend run check
    '
