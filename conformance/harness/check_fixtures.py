#!/usr/bin/env python3
"""Validate fixture policy descriptors against the specification's JSON Schemas.

Requires the jsonschema package. Placeholders such as "{port}" are rendered
with sample values before validation; the audit schema is checked against the
examples in spec/draft/audit.md.
"""
import json
import os
import re
import sys

import jsonschema

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
SCHEMA_DIR = os.path.join(ROOT, "spec", "draft", "schema")
FIXTURE_DIR = os.path.join(ROOT, "conformance", "fixtures")


def render(value):
    if isinstance(value, str):
        if value == "{port}":
            return 4443
        if value == "{udp_enabled}":
            return False
        return value.replace("{target4}", "192.0.2.10").replace("{target6}", "2001:db8::10")
    if isinstance(value, list):
        return [render(v) for v in value]
    if isinstance(value, dict):
        return {k: render(v) for k, v in value.items()}
    return value


def main():
    validator = jsonschema.Draft202012Validator
    with open(os.path.join(SCHEMA_DIR, "policy.schema.json")) as f:
        policy_schema = json.load(f)
    with open(os.path.join(SCHEMA_DIR, "audit.schema.json")) as f:
        audit_schema = json.load(f)
    validator.check_schema(policy_schema)
    validator.check_schema(audit_schema)
    policy_validator = validator(policy_schema)
    audit_validator = validator(audit_schema)
    problems = 0

    for name in sorted(os.listdir(FIXTURE_DIR)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(FIXTURE_DIR, name)) as f:
            fixture = json.load(f)
        descriptors = {}
        for key, entry in fixture.get("policies", {}).items():
            descriptors[key] = entry["descriptor"] if "descriptor" in entry else entry
        if "policy" in fixture.get("environment", {}):
            descriptors["environment"] = fixture["environment"]["policy"]
        for key, descriptor in descriptors.items():
            for error in policy_validator.iter_errors(render(descriptor)):
                print(f"{name}: policy {key}: {error.message}")
                problems += 1
        ids = [case["id"] for case in fixture["cases"]]
        for duplicate in {i for i in ids if ids.count(i) > 1}:
            print(f"{name}: duplicate case id {duplicate}")
            problems += 1
        for case in fixture["cases"]:
            if "policy" in case and case["policy"] not in descriptors:
                print(f"{name}: {case['id']} names unknown policy {case['policy']}")
                problems += 1

    with open(os.path.join(ROOT, "spec", "draft", "audit.md")) as f:
        for line in f:
            if line.startswith("{"):
                for error in audit_validator.iter_errors(json.loads(line)):
                    print(f"audit.md example: {error.message}")
                    problems += 1

    print("fixture problems:", problems)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
