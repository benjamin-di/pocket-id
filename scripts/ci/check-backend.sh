#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
go_image='golang:1.27.3@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e'
postgres_image='postgres:17-alpine@sha256:f9cf3e1f0066f0eb0c48707d864f0ac5941e9ff454a072077d97a4d278d07d73'

network="pocket-id-backend-ci-$$"
pg_container="pocket-id-pg-ci-$$"
cache_dir="$(mktemp -d "${TMPDIR:-/tmp}/pocket-id-go-cache.XXXXXX")"

cleanup() {
    docker rm -fv "$pg_container" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
    chmod -R u+w "$cache_dir" >/dev/null 2>&1 || true
    rm -rf "$cache_dir"
}
trap cleanup EXIT

mkdir -p "$cache_dir/home" "$cache_dir/build" "$cache_dir/mod"
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
    -v "$cache_dir:/go-cache" \
    -w /src/backend \
    -e HOME=/go-cache/home \
    -e GOCACHE=/go-cache/build \
    -e GOMODCACHE=/go-cache/mod \
    -e GOFLAGS=-modcacherw \
    -e CGO_ENABLED=0 \
    -e POCKET_ID_TEST_POSTGRES_URL='postgres://postgres:postgres@postgres:5432/postgres?sslmode=disable' \
    "$go_image" \
    go test -count=1 -tags=exclude_frontend,unit ./...
