# Deployment fork

`main` follows upstream. `fleet` is the deployable branch: the stable 2.19.1 release,
upstream security updates, and the upstream contributions listed in
[fork-patches.json](fork-patches.json). Application-specific configuration and
identity data belong in the deployment repository, never here.

The branch carries the existing claim-mapping PR rather than a separate identity
implementation. The Fosite replacement is pinned to one reviewed public commit.
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

CI tests the backend against SQLite and the available PostgreSQL service, builds
the frontend and runs its type checks. Tag a green `fleet` commit as
`v<upstream>-fleet.<n>` after updating `.version`. `fleet-release.yml` requires that
CI result and publishes the amd64 image with source, revision and version labels;
it never deploys a service. Consumers pin the immutable digest and rehearse upgrade
and rollback on a disposable state copy before deployment.

The deployment owner's shared CI actions are private and unavailable to a public
fork. These workflows use public upstream actions; the release job queries the
repository's CI run for the exact tagged commit and refuses failed or missing CI.
It never repeats the test suite during release.
