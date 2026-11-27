#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
go_image='golang:1.27.4@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666'
postgres_image='postgres:17-alpine@sha256:f9cf3e1f0066f0eb0c48707d864f0ac5941e9ff454a072077d97a4d278d07d73'

network="pocket-id-backend-ci-$$"
pg_container="pocket-id-pg-ci-$$"
home_dir="$(mktemp -d "${TMPDIR:-/tmp}/pocket-id-go-home.XXXXXX")"
ephemeral_cache=false
if [ -n "${FLEET_GO_CACHE_DIR:-}" ]; then
    cache_dir="$FLEET_GO_CACHE_DIR"
elif [ -d /var/lib/jenkins/.cache/fleet-packages ] && [ -w /var/lib/jenkins/.cache/fleet-packages ]; then
    cache_dir="/var/lib/jenkins/.cache/fleet-packages/go"
else
    cache_dir="$(mktemp -d "${TMPDIR:-/tmp}/pocket-id-go-cache.XXXXXX")"
    ephemeral_cache=true
fi

cleanup() {
    docker rm -fv "$pg_container" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
    chmod -R u+w "$home_dir" >/dev/null 2>&1 || true
    rm -rf "$home_dir"
    if [ "$ephemeral_cache" = true ]; then
        chmod -R u+w "$cache_dir" >/dev/null 2>&1 || true
        rm -rf "$cache_dir"
    fi
}
trap cleanup EXIT

mkdir -p "$home_dir" "$cache_dir/build" "$cache_dir/mod"
docker network create "$network" >/dev/null

docker run -d \
    --name "$pg_container" \
    --network "$network" \
    --network-alias postgres \
    -e POSTGRES_PASSWORD=postgres \
    "$postgres_image" >/dev/null

ready=false
for _ in $(seq 1 30); do
    if docker exec "$pg_container" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 1
done
if [ "$ready" != true ]; then
    echo 'PostgreSQL test container did not become ready' >&2
    docker logs "$pg_container" >&2 || true
    exit 1
fi

docker run --rm \
    --network "$network" \
    --user "$(id -u):$(id -g)" \
    -v "$root:/src:ro" \
    -v "$home_dir:/go-home" \
    -v "$cache_dir:/go-cache" \
    -w /src/backend \
    -e HOME=/go-home \
    -e GOCACHE=/go-cache/build \
    -e GOMODCACHE=/go-cache/mod \
    -e GOFLAGS=-modcacherw \
    -e CGO_ENABLED=0 \
    -e POCKET_ID_TEST_POSTGRES_URL='postgres://postgres:postgres@postgres:5432/postgres?sslmode=disable' \
    "$go_image" \
    go test -count=1 -tags=exclude_frontend,unit ./...
