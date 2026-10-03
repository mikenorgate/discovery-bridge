# Contract fixtures

These fixed inputs and expected outputs preserve the discovery boundary across
implementation and packaging changes. `make test` reads them directly; no fixture
generator is required for ordinary builds or qualification.

- `views.json`: complete and incomplete DNS-SD graphs, ambiguity and TTL bounds.
- `identities.json`: stable host and service aliases, collisions and invalid UTF-8.
- `identity-state.json`: persisted identity rows and reservation wire names.
- `publication.json`: complete local publisher frame and DNS wire signatures.
- `services.json`: selected external Service intent and resulting DNS records.

Addresses use documentation networks. Timestamps, epochs and boot identifiers are
synthetic. Changes to expected outputs require review against the compatibility
contract; do not regenerate them just to make a test pass.
