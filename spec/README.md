# agents.net Specification Versions

The specification is organized like other protocol specifications that evolve
in public: one always-moving draft and frozen releases.

| Directory | Meaning |
| --- | --- |
| [draft/](draft/) | The working version. Changes land here. Its documents carry **Version: 1 (draft)** until the first release. |
| `v1/`, `v2/`, ... | Frozen copies made at release. A released directory is never edited except for errata recorded in its `ERRATA.md`. |

## Release Rules

1. A release requires that the [conformance suite](../conformance/README.md)
   at the matching version has fixtures for every profile in the release and
   that at least two independent implementations pass `boundary-core`.
2. Releasing copies `draft/` to `v<N>/`, sets **Version: N** in every
   document, and records the date and the suite version in `v<N>/index.md`.
   `draft/` continues as the working copy of the next version.
3. The schema version fields `agents_net_policy` and `agents_net_audit`
   equal the specification major version. They increment only on an
   incompatible change; a release without such a change keeps them.
4. Implementation statements name the specification version and the suite
   version they were produced against.

## Changing the Draft

Normative changes are proposed as a design note in [docs/](../docs/) or a pull
request against `draft/`, and land together with the conformance fixtures
that verify them. Products and deployments are described only in informative
documents outside `spec/`.
