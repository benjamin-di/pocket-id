# Compatibility rollback runtime

Stable upstream authentication code at 32c4d7f7 plus the actual additive claim-mapping schema migration, generic CIMD authentication negotiation (pocket-id/pocket-id#1874) and the Fosite grant-context fix (pocket-id/fosite#4). This image recognizes the database version after the feature upgrade without replacing or restoring user data. It does not implement claim-mapping APIs or refresh authorization groups. Before using it as a fallback after group enforcement has been enabled, restore the gateway policy that uses immutable subjects. Never trust its refreshed tokens for group-based authorization.

This branch is a rollback artifact, not the normal deployment branch. `fleet` carries the reviewed upstream contributions. Both artifacts require green CI and immutable source/version/revision image labels.

The deployment owner's shared CI actions are private and unavailable to a public
fork. These workflows use public upstream actions; the release job queries the
repository's CI run for the exact tagged commit and refuses failed or missing CI.
It never repeats the test suite during release.

The generic authentication fixes preserve newly enrolled metadata clients during fallback. The superseded fleet.1 image lacks those fixes; use the fleet.3 compatibility artifact. The normal feature image remains fleet.2. Always select the explicit reviewed artifact rather than inferring its purpose from tag order.
