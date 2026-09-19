# agents.net Specification Versions

Like most protocol specifications that evolve in public, this one has a single
moving draft and a set of frozen releases.

| Directory | Meaning |
| --- | --- |
| [draft/](draft/) | The working version. Changes land here. Its documents carry **Version: 1 (draft)** until the first release. |
| `v1/`, `v2/`, ... | Frozen copies made at release. A released directory is never edited except for errata recorded in its `ERRATA.md`. |

## Release Rules

1. Do not release until the [conformance suite](../conformance/README.md) at
   the matching version has fixtures for every profile in the release, and
   at least two independent implementations pass `boundary-core`.
2. To release, copy `draft/` to `v<N>/`, set **Version: N** in every
   document, and record the release date and the suite version in
   `v<N>/index.md`. `draft/` then becomes the working copy of the next
   version.
3. The schema version fields `agents_net_policy` and `agents_net_audit`
   equal the specification major version. Increment them only for an
   incompatible change. A release with no such change keeps the current
   values.
4. An implementation statement names the specification version and the
   suite version it was produced against.
5. While `draft/` carries `agents_net_policy: 1`, changes to the descriptor,
   the audit record, the reason token registry, and the authorization
   algorithm are additive only: new optional fields, new tokens, new
   profiles. Any change that would alter the decision an existing descriptor
   produces, or make an existing record or token invalid, increments the
   schema version and goes out as the next major version. A deployment that
   ships against the draft can keep its descriptors.

## Changing the Draft

Propose a normative change either as a design note in [docs/](../docs/) or as
a pull request against `draft/`. The change lands together with the
conformance fixtures that verify it. Descriptions of products and deployments
belong in informative documents outside `spec/`.
