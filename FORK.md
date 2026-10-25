# Compatibility rollback runtime

Stable upstream authentication code at 32c4d7f7 plus the actual additive claim-mapping schema migration. This image recognizes the database version after the feature upgrade without replacing or restoring user data. It does not implement claim-mapping APIs or refresh authorization groups. Before using it as a fallback after group enforcement has been enabled, restore the gateway policy that uses immutable subjects. Never trust its refreshed tokens for group-based authorization.

This branch is a rollback artifact, not the normal deployment branch. `fleet` carries the reviewed upstream contributions. Both artifacts require green CI and immutable source/version/revision image labels.
