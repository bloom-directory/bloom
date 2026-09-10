"""Validate release versions and render notes from the reviewed source tree."""

import argparse
import json
import re
import subprocess
import tomllib
from pathlib import Path


def check_versions(matrix, version):
    bundles = matrix["bundles"]
    if len(bundles) != 1:
        raise ValueError("release requires exactly one triad bundle")
    for component in ("machine", "broker", "signer"):
        actual = bundles[0][component]
        if actual != version:
            raise ValueError(
                f"{component} version {actual} must match release {version}; "
                "bump all three binaries and update the reviewed compatibility pins"
            )


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def previous_release(releases, tag, sha):
    current = next((r for r in releases if r["tag_name"] == tag), None)
    candidates = sorted(
        (r for r in releases if not r["draft"] and not r["prerelease"]
         and r["tag_name"] != tag
         and re.fullmatch(r"v\d+\.\d+\.\d+", r["tag_name"])
         and (current is None or r["published_at"] < current["published_at"])),
        key=lambda r: r["published_at"], reverse=True,
    )
    for release in candidates:
        ref = f"refs/tags/{release['tag_name']}"
        revision = git("rev-parse", "--verify", f"{ref}^{{commit}}")
        if revision != sha and subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, sha], check=False
        ).returncode == 0:
            return release["tag_name"]
    return None


def notes(matrix, version, repository, sha, previous):
    lines = [f"## Bloom v{version}", "",
             "This release contains signed Bloom triad bundles for Linux x86_64 and macOS aarch64.",
             "", f"Machine, Broker, and Signer binary version: `{version}`.", "",
             "### IPC protocol versions", ""]
    for key, label in (("machine_broker", "Machine → Broker"),
                       ("broker_signer", "Broker → Signer")):
        protocol = matrix["protocols"][key]
        low = f"{protocol['major']}.{protocol['minor_min']}"
        high = f"{protocol['major']}.{protocol['minor_max']}"
        lines.append(f"- {label}: `{low}`" + (f"–`{high}`" if low != high else ""))
    lines += ["", "Verify the archive checksum signature with the reviewed key at",
              "`packaging/triad/release/bloom-release-v1.pub` and the namespace",
              "`bloom-release-archive-v1`.", "", "### Changelog", ""]
    if previous:
        lines += [f"All Bloom commits since [{previous}](https://github.com/{repository}/releases/tag/{previous}).", ""]
    else:
        lines += ["First release: all Bloom commits through this release.", ""]
    revision_range = f"refs/tags/{previous}..{sha}" if previous else sha
    for commit in git("log", "--reverse", "--format=%H %s", revision_range, "--").splitlines():
        revision, subject = commit.split(" ", 1)
        subject = re.sub(r"([\\`*_{}\[\]<>])", r"\\\1", subject)
        lines.append(f"- [{revision[:12]}](https://github.com/{repository}/commit/{revision}) {subject}")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "notes"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository")
    parser.add_argument("--sha")
    parser.add_argument("--releases", type=Path)
    args = parser.parse_args()
    matrix = tomllib.loads(Path("packaging/triad/release/compatibility-v1.toml").read_text())
    check_versions(matrix, args.version)
    if args.command == "notes":
        releases = [release for page in json.loads(args.releases.read_text()) for release in page]
        previous = previous_release(releases, f"v{args.version}", args.sha)
        print(notes(matrix, args.version, args.repository, args.sha, previous), end="")


if __name__ == "__main__":
    main()
