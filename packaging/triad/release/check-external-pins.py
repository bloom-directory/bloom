#!/usr/bin/env python3
"""Fail closed when triad Git dependencies or recorded revisions drift.

The compatibility matrix records the authority stack a bundle must attest.
This checker proves the workspace manifests agree with it: every role the
provided manifests can pin (Broker API, Signer API, service-runtime, Petal
contract) must pin exactly the recorded revision, and every manifest must
agree with every other. Machine-only invocations cannot see the Signer pin
(the Machine workspace does not depend on it); the full triad gate invokes
this script with all three workspace manifests, at which point every role is
cross-checked.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tomllib
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[3]
COMPAT = ROOT / "packaging/triad/release/compatibility-v1.toml"
FULL = re.compile(r"^[0-9a-f]{40}$")

# Which manifest dependency names pin each recorded revision, and which
# GitHub repository the revision must exist in.
REVISION_ROLES = {
    "broker_commit": (
        "bloom-directory/bloom-broker",
        ("bloom-broker-api",),
    ),
    "signer_commit": (
        "bloom-directory/bloom-signer",
        ("bloom-signer-api", "bloom-signer-vectors"),
    ),
    "service_runtime_commit": (
        "bloom-directory/bloom-service-runtime",
        ("bloom-audit-checkpoint", "bloom-rpc-wire", "bloom-triad-local-transport",
         "bloom-service-activation", "bloom-service-observability",
         "bloom-trusted-time", "bloom-platform-containment"),
    ),
    "petal_contract_commit": (
        "bloom-directory/petal",
        ("bloom-petal-contract",),
    ),
}


def fail(message: str) -> None:
    raise SystemExit(message)


def dependency_tables(document: dict) -> list[dict]:
    tables = []
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = document.get(key, {})
        if isinstance(value, dict):
            tables.append(value)
    workspace = document.get("workspace", {})
    if isinstance(workspace, dict):
        value = workspace.get("dependencies", {})
        if isinstance(value, dict):
            tables.append(value)
    return tables


def check_manifest_pins(path: pathlib.Path) -> dict[str, str]:
    """Validate one manifest's Git pins and return name -> revision."""
    document = tomllib.loads(path.read_text())
    pins: dict[str, str] = {}
    for table in dependency_tables(document):
        for name, spec in table.items():
            if not isinstance(spec, dict) or "git" not in spec:
                continue
            if "branch" in spec or "tag" in spec:
                fail(f"{path}: Git dependency {name} uses a mutable branch or tag")
            revision = spec.get("rev")
            if not isinstance(revision, str) or not FULL.fullmatch(revision):
                fail(f"{path}: Git dependency {name} is not pinned to a full commit")
            repository = str(spec["git"]).rstrip("/").rsplit("/", 1)[-1]
            if repository.endswith(".git"):
                repository = repository[: -len(".git")]
            expected_repository = next(
                (
                    repo.rsplit("/", 1)[-1]
                    for repo, names in REVISION_ROLES.values()
                    if name in names
                ),
                None,
            )
            if expected_repository is not None and repository != expected_repository:
                fail(
                    f"{path}: dependency {name} must come from "
                    f"{expected_repository}, not {repository}"
                )
            previous = pins.setdefault(name, revision)
            if previous != revision:
                fail(f"{path}: dependency {name} is pinned to conflicting revisions")
    return pins


def remote_commit_exists(repository: str, revision: str) -> None:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/commits/{revision}",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "bloom-pin-audit"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200:
                fail(f"{repository}@{revision}: GitHub returned {response.status}")
    except (urllib.error.URLError, TimeoutError) as error:
        fail(f"{repository}@{revision}: commit is unavailable: {error}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote", action="store_true", help="also prove each commit through GitHub")
    parser.add_argument("manifests", nargs="*", type=pathlib.Path)
    args = parser.parse_args()

    compatibility = tomllib.loads(COMPAT.read_text())
    revisions = compatibility.get("revisions")
    if not isinstance(revisions, dict):
        fail("compatibility manifest has no revisions table")

    roots = args.manifests or [ROOT / "Cargo.toml"]
    manifests: set[pathlib.Path] = set()
    for root_manifest in roots:
        root_manifest = root_manifest.resolve()
        manifests.add(root_manifest)
        manifests.update(
            path
            for path in root_manifest.parent.rglob("Cargo.toml")
            if "target" not in path.parts and ".git" not in path.parts
        )

    observed: dict[str, dict[str, str]] = {role: {} for role in REVISION_ROLES}
    for manifest in sorted(manifests):
        pins = check_manifest_pins(manifest)
        for role, (_, names) in REVISION_ROLES.items():
            for name in names:
                if name in pins:
                    previous = observed[role].setdefault(name, pins[name])
                    if previous != pins[name]:
                        fail(
                            f"{role}: {name} is pinned to {pins[name]} in {manifest} "
                            f"but {previous} elsewhere; the workspaces disagree"
                        )

    for role, (repository, _) in REVISION_ROLES.items():
        recorded = revisions.get(role)
        if not isinstance(recorded, str) or not FULL.fullmatch(recorded):
            fail(f"compatibility revision {role} is missing, mutable, or unexpected")
        for name, revision in observed[role].items():
            if revision != recorded:
                fail(
                    f"{role}: manifest pins {name}@{revision} but the compatibility "
                    f"matrix records {recorded}; update them together"
                )
        if args.remote:
            remote_commit_exists(repository, recorded)

    print("triad external dependency pins are immutable and compatible")


if __name__ == "__main__":
    main()
