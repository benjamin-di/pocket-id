#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
vite_plus_image='ghcr.io/voidzero-dev/vite-plus:1.4.0@sha256:5dfa2031f7d014b6376407fd99e0747bed329d792c79c184a65ec9a0765bee0e'

docker run --rm \
    -e CI=true \
    -v "$root:/src:ro" \
    "$vite_plus_image" \
    sh -eu -c '
        work="$(mktemp -d)"
        trap "rm -rf \"$work\"" EXIT
        mkdir -p "$work/frontend" "$work/tests" "$work/email-templates"
        cp /src/package.json /src/pnpm-workspace.yaml /src/pnpm-lock.yaml /src/.node-version "$work/"
        cp /src/tests/package.json "$work/tests/"
        cp /src/email-templates/package.json "$work/email-templates/"
        cp -r /src/frontend/. "$work/frontend/"
        cd "$work"
        vp -C frontend install --frozen-lockfile
        vp -C frontend run build
        vp -C frontend run check
    '
