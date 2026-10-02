# Python behavior reference

This is a sanitized snapshot used to check the Go port. Its fixed network
values are synthetic fixtures. Deployment configuration and production evidence
are not included. The source uses a neutral pod label and naming prefix.

Run `python3 -m unittest discover -s tests -v` in this directory after installing
`requirements-test.txt` with hashes. The suite contains 252 behavior tests. Two
tests that depend on a private infrastructure repository stay with that
repository's integration tests.

The snapshot will leave the active build after the complete Go runtime passes
its compatibility and deployment checks. Its Git tag preserves the reference.
