# Deployment fork

`main` follows upstream. `fleet` is the deployable branch: the stable 2.19.2 release and the upstream contributions listed in
[fork-patches.json](fork-patches.json). Application-specific configuration and
identity data belong in the deployment repository, never here.

The branch carries the existing claim-mapping PR rather than a separate identity
implementation. The Fosite replacement is pinned to a v1.6.0 source assembly retaining the still-open
consented-grant and expiry fixes. The Go pseudo-version reflects the fork's nearest
published tag; the exact source baseline and consumed commit are in the ledger.
API-scope mappings use the provider's existing OAuth scope parser, exact granted
scope matching and per-client policy assignment. Built-in token claims, resource
audiences and machine/user separation remain owned by their existing layers.

PKCE accepts and advertises only `S256`, following RFC 9700 section 4.8.2.
The proposal is tracked in [upstream issue #1886](https://github.com/pocket-id/pocket-id/issues/1886).
This intentionally removes the legacy `plain` compatibility introduced after
upstream issue #1534; that closed issue is context, not an upstream S256-only
implementation. Both explicit `plain` and an omitted method with a challenge are
rejected. Confidential clients without a PKCE requirement, refresh grants,
device authorization and client credentials retain their existing behavior.

Before updating upstream, review each patch's retirement condition. Adopt merged
upstream implementations and delete the corresponding local patch. Keep the
PKCE, refresh, disclosure, machine-token and migration regressions passing.
Upstream contribution branches must exclude release workflows and deployment files.

CI tests the backend against SQLite and PostgreSQL (`scripts/ci/check-backend.sh`),
builds the frontend and runs its type checks (`scripts/ci/check-frontend.sh`).
Tag a green `fleet` commit as `v<upstream>-fleet.<n>` after updating `.version`.
`.github/jenkins/Jenkinsfile` requires an exact-source green `fleet` check, builds
and smoke-tests the image (`scripts/ci/smoke-image.sh`) with source, revision and
version labels, and promotes the immutable release tag; it never deploys a service.
Consumers pin the immutable digest and rehearse upgrade and rollback on a disposable
state copy before deployment.

Tag builds verify the exact tagged commit's passing `fleet` CI result before
building and promoting the image, refusing failed or missing CI without repeating
the test suite during release.

CIMD follows the upstream draft-03 implementation from `69d23106` and `5194ffc4`,
with token/consent revocation prerequisite `3646c5d2`. The superseded #1874
negotiation implementation is removed. This includes minimum caching, stale-on-outage
limits, client ID mismatch revocation, API-audience collision rejection and rejection
of authentication credentials from metadata clients. Only the stable resource
normalization and test constructor require API adaptations. No unrelated main
ancestry is merged. Independent authentication review and immutable publication
remain required before consumer adoption.
