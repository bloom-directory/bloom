#!/usr/bin/env python3
"""Fail closed when triad Git dependencies or recorded revisions drift."""

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
EXPECTED = {
    "broker_commit": ("bloom-directory/bloom-broker", "77c30ccedbd6904c0f2f2ad19e48c5587061b04e"),
    "signer_commit": ("bloom-directory/bloom-signer", "f5139960b9c5b59803ad54a1ecc9ef4e86f82d0c"),
    "service_runtime_commit": ("bloom-directory/bloom-service-runtime", "d2542a07a988261fe2f82b738462de2127b317d2"),
    "petal_contract_commit": ("bloom-directory/petal", "61938d0c127cfe03c7e3e55baed0ba1439bc5ca2"),
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


def check_manifest(path: pathlib.Path) -> None:
    document = tomllib.loads(path.read_text())
    for table in dependency_tables(document):
        for name, spec in table.items():
            if not isinstance(spec, dict) or "git" not in spec:
                continue
            if "branch" in spec or "tag" in spec:
                fail(f"{path}: Git dependency {name} uses a mutable branch or tag")
            revision = spec.get("rev")
            if not isinstance(revision, str) or not FULL.fullmatch(revision):
                fail(f"{path}: Git dependency {name} is not pinned to a full commit")


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
    for name, (repository, expected) in EXPECTED.items():
        actual = revisions.get(name)
        if actual != expected or not isinstance(actual, str) or not FULL.fullmatch(actual):
            fail(f"compatibility revision {name} is missing, mutable, or unexpected")
        if args.remote:
            remote_commit_exists(repository, actual)

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
    for manifest in sorted(manifests):
        check_manifest(manifest)
    print("triad external dependency pins are immutable and compatible")


if __name__ == "__main__":
    main()
