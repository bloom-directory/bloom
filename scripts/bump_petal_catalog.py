#!/usr/bin/env python3
"""Advance preinstalled petal pins in crates/bloom/src/github_source.rs.

For each automatically upgradable preinstalled petal, resolve the latest
semver release of its source repository, download the release assets,
verify them against SHA256SUMS and the petal-release.json provenance
manifest, and only then rewrite the pinned commit, release tag, archive
name, and expected hash (the BLAKE3 package_hash, which is what the
installer compares) in the source constants.

Petals whose upgrade policy is ManualStateMigration are never touched:
their package state is keyed by content hash and requires an explicit
quiescence and migration flow before Bloom may change its owner record.

Exits non-zero on any provenance or parse failure. Exits 0 with no edits
when every pin already matches the latest release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# petal.toml name -> source repository (owner/name). Keep in sync with the
# PREINSTALLED_* constants in crates/bloom/src/github_source.rs. Petals with
# upgrade_policy ManualStateMigration (currently hyperliquid) must NOT be
# listed here.
AUTO_PETALS: list[tuple[str, str]] = [
    ("near-intents", "bloom-directory/bloom-petal-near"),
    ("enso", "bloom-directory/bloom-petal-enso"),
]

PROVENANCE_SCHEMA = "bloom.petal.release.v1"


def gh(*args: str) -> str:
    result = subprocess.run(
        ["gh", *args], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"gh {' '.join(args)} failed: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


def parse_semver(tag: str) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def latest_semver_release(repo: str) -> str:
    releases = json.loads(
        gh("release", "list", "-R", repo, "--json", "tagName,isPrerelease,isDraft")
    )
    tagged = [
        release["tagName"]
        for release in releases
        if not release["isPrerelease"] and not release["isDraft"]
    ]
    versions = [(parse_semver(tag), tag) for tag in tagged]
    versions = [(v, t) for v, t in versions if v is not None]
    if not versions:
        raise RuntimeError(f"{repo}: no semver releases found")
    versions.sort()
    return versions[-1][1]


def block_field(block: str, field: str) -> str | None:
    match = re.search(rf'{field}: "([^"]+)"', block)
    return match.group(1) if match else None


def rewrite_block(source: str, petal: str, commit: str, tag: str, archive: str, sha256: str) -> str:
    """Rewrite one PREINSTALLED_* const block (and its named commit const)."""
    chunks = source.split("PreinstalledPetal {")
    for index in range(1, len(chunks)):
        block_end = chunks[index].find("};")
        block = chunks[index][:block_end]
        if block_field(block, "name") != petal:
            continue

        new_block = block
        new_block = re.sub(r'(release_tag: ")[^"]+(")', r"\g<1>" + tag + r"\g<2>", new_block)
        new_block = re.sub(r'(archive: ")[^"]+(")', r"\g<1>" + archive + r"\g<2>", new_block)
        new_block = re.sub(
            r'(expected_hash: Some\(")[0-9a-f]{64}("\))',
            r"\g<1>" + sha256 + r"\g<2>",
            new_block,
        )

        commit_match = re.search(r"commit: ([A-Za-z_][A-Za-z0-9_]*)", new_block)
        if commit_match:
            const_name = commit_match.group(1)
            preamble = chunks[0]
            new_preamble, count = re.subn(
                r'(const ' + const_name + r': &str = ")[0-9a-f]{40}(")',
                r"\g<1>" + commit + r"\g<2>",
                preamble,
            )
            if count != 1:
                raise RuntimeError(
                    f"{petal}: expected exactly one `const {const_name}` definition, found {count}"
                )
            chunks[0] = new_preamble
        else:
            new_block = re.sub(r'(commit: ")[0-9a-f]{40}(")', r"\g<1>" + commit + r"\g<2>", new_block)

        chunks[index] = new_block + chunks[index][block_end:]
        rebuilt = [chunks[0]] + [f"PreinstalledPetal {{{chunk}" for chunk in chunks[1:]]
        return "".join(rebuilt)

    raise RuntimeError(f"{petal}: no PREINSTALLED_* block found in source")


def verify_release(petal: str, repo: str, tag: str) -> tuple[str, str, str, str]:
    """Download and verify release assets; return (commit, tag, archive, sha256)."""
    with tempfile.TemporaryDirectory() as tmp:
        gh(
            "release", "download", tag, "-R", repo, "-D", tmp,
            "--pattern", "petal-release.json",
            "--pattern", "SHA256SUMS",
            "--pattern", "*.petal.tar.gz",
        )
        root = Path(tmp)
        provenance = json.loads((root / "petal-release.json").read_text())

        if provenance.get("schema") != PROVENANCE_SCHEMA:
            raise RuntimeError(f"{petal}: unexpected provenance schema {provenance.get('schema')!r}")
        if provenance.get("petal_name") != petal:
            raise RuntimeError(
                f"{petal}: provenance petal_name {provenance.get('petal_name')!r} does not match"
            )
        if provenance.get("release_tag") != tag:
            raise RuntimeError(
                f"{petal}: provenance release_tag {provenance.get('release_tag')!r} != {tag}"
            )
        archive_name = provenance.get("archive")
        expected_archive = f"{petal}-{tag}.petal.tar.gz"
        if archive_name != expected_archive:
            raise RuntimeError(f"{petal}: archive {archive_name!r} != expected {expected_archive!r}")
        commit = provenance.get("source_commit")
        if not re.fullmatch(r"[0-9a-f]{40}", commit or ""):
            raise RuntimeError(f"{petal}: provenance source_commit is not a 40-hex sha")
        if provenance.get("tooling_repository") != "bloom-directory/petal":
            raise RuntimeError(f"{petal}: provenance tooling_repository is not bloom-directory/petal")

        checksums = {}
        for line in (root / "SHA256SUMS").read_text().splitlines():
            if line.strip():
                digest, _, name = line.partition("  ")
                checksums[name.strip()] = digest.strip()
        if set(checksums) != {archive_name}:
            raise RuntimeError(f"{petal}: SHA256SUMS lists {sorted(checksums)}, expected only {archive_name}")

        archive_path = root / archive_name
        digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        if digest != checksums[archive_name]:
            raise RuntimeError(f"{petal}: archive digest does not match SHA256SUMS")
        if digest != provenance.get("archive_sha256"):
            raise RuntimeError(f"{petal}: archive digest does not match provenance archive_sha256")

        # Production compares expected_hash with the manifest package_hash
        # (BLAKE3 package identity), not the archive SHA-256, so that is the
        # value the catalog pin must carry.
        package_hash = provenance.get("package_hash")
        if not re.fullmatch(r"[0-9a-f]{64}", package_hash or ""):
            raise RuntimeError(f"{petal}: provenance package_hash is not a 64-hex digest")

        return commit, tag, archive_name, package_hash


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        default="crates/bloom/src/github_source.rs",
        help="path to github_source.rs",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="verify and print without writing"
    )
    args = parser.parse_args()

    source_path = Path(args.source)
    source = source_path.read_text()
    changed = False

    for petal, repo in AUTO_PETALS:
        tag = latest_semver_release(repo)
        # The current tag must be read from the full const block (up to
        # `};`), not from a match that ends at the name field.
        chunks = source.split("PreinstalledPetal {")
        current_tag = None
        for chunk in chunks[1:]:
            block = chunk[: chunk.find("};")]
            if block_field(block, "name") == petal:
                current_tag = block_field(block, "release_tag")
                break
        if current_tag is None and not any(
            block_field(c[: c.find("};")], "name") == petal for c in chunks[1:]
        ):
            raise RuntimeError(f"{petal}: no PREINSTALLED_* block found in source")
        if current_tag == tag:
            print(f"{petal}: up to date at {tag}")
            continue

        commit, tag, archive, sha256 = verify_release(petal, repo, tag)
        source = rewrite_block(source, petal, commit, tag, archive, sha256)
        print(f"{petal}: {current_tag} -> {tag} (commit {commit[:12]}, sha256 {sha256[:12]}...)")
        changed = True

    if changed and not args.dry_run:
        source_path.write_text(source)
        print(f"wrote {source_path}")
    elif changed:
        print("dry run: no files written")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print(f"::error::{error}", file=sys.stderr)
        sys.exit(1)
