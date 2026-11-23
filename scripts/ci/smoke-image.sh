#!/usr/bin/env bash
set -euo pipefail

image="${1:?image digest required}"
revision="${2:?source revision required}"
version="${3:?package version required}"

[[ "$image" =~ @sha256:[a-f0-9]{64}$ ]] || { echo 'An exact image digest is required' >&2; exit 2; }
docker pull --quiet "$image" >/dev/null
[ "$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")" = "$revision" ]
[ "$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$image")" = "$version" ]

actual_version="$(docker run --rm --network none --read-only --user 1000:1000 "$image" /app/pocket-id version)"
[ "$actual_version" = "pocket-id $version" ] || {
    echo "Expected 'pocket-id $version', got '$actual_version'" >&2
    exit 1
}

container="pocket-id-smoke-$$"
smoke_key="$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"
cleanup() {
    docker rm -fv "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d \
    --name "$container" \
    --network none \
    --read-only \
    --user 1000:1000 \
    --tmpfs /app/data:rw,size=64m,uid=1000,gid=1000 \
    --tmpfs /tmp:rw,size=32m,uid=1000,gid=1000 \
    -e APP_URL=https://id.example.test \
    -e "ENCRYPTION_KEY=$smoke_key" \
    -e DB_CONNECTION_STRING=file:/app/data/pocket-id.db \
    -e ANALYTICS_DISABLED=true \
    -e VERSION_CHECK_DISABLED=true \
    -e ICON_LIBRARY_URL=disabled \
    "$image" >/dev/null

healthy=false
for _ in $(seq 1 30); do
    if docker exec "$container" /app/pocket-id healthcheck >/dev/null 2>&1; then
        healthy=true
        break
    fi
    sleep 1
done
if [ "$healthy" != true ]; then
    echo 'Pocket ID container failed healthcheck during image smoke test' >&2
    docker logs "$container" >&2 || true
    exit 1
fi
