# Upgrade and upstream synchronization

Upstream source synchronization is governed by `CODESTRA_UPSTREAM.json`, `CODESTRA_UPSTREAM_LOCK.json` and the protected synchronization workflow. A runtime upgrade is a separate change:

1. select an upstream release and resolve its tag to an exact commit;
2. resolve the multi-platform image to an exact manifest-list digest and record the target platform manifest;
3. scan the exact digest and verify upstream signatures/provenance when published;
4. update the runtime lock, configuration compatibility tests and release evidence together;
5. validate `amtool check-config` using that digest and run the routing regression suite;
6. merge and promote through protected lineage before publishing a signed Codestra configuration artifact;
7. retain the previous pullable digest and configuration artifact for rollback.

Never synchronize a floating upstream branch directly into a protected branch, and never use a mutable image tag as the runtime identity.
