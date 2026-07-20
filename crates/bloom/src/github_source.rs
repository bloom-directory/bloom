use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use bloom_daemon::Daemon;
use bloom_petals::meta::PetalSourceProvenance;
use bloom_petals::package::{
    PetalConsentSummary, PreparedPetalPackage, RouteIndex, petal_consent_summary,
};
use bloom_proto::HomeDir;
use serde::Deserialize;
use url::Url;

const TRUSTED_GITHUB_OWNER: &str = "bloom-directory";
const POLYMARKET_PARITY_COMMIT: &str = "1ffb267a1e1d4acd137c184806c20cc98d20a3f4";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreinstalledPetal {
    pub name: &'static str,
    pub repository: &'static str,
    pub commit: &'static str,
    pub expected_hash: Option<&'static str>,
}

const PREINSTALLED_POLYMARKET: PreinstalledPetal = PreinstalledPetal {
    name: "polymarket",
    repository: "https://github.com/bloom-directory/bloom-petal-polymarket",
    commit: POLYMARKET_PARITY_COMMIT,
    // Source builds are verified by immutable commit and recorded package
    // provenance. Add a package hash when release builds are reproducible
    // across every supported host toolchain.
    expected_hash: None,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitHubRepo {
    pub owner: String,
    pub repo: String,
    pub canonical_url: String,
    pub clone_url: String,
}

#[derive(Debug)]
pub(crate) struct GitHubInstallOutput {
    pub result: bloom_petals::store::InstallResult,
    pub meta: bloom_petals::meta::PetalMeta,
    pub index: RouteIndex,
    pub consent: PetalConsentSummary,
    pub provenance: PetalSourceProvenance,
}

#[derive(Debug, Deserialize)]
struct SourcePetalToml {
    #[serde(default)]
    schema: Option<String>,
    #[serde(default)]
    source: Option<SourceSection>,
    #[serde(default)]
    build: Option<BuildSection>,
}

#[derive(Debug, Deserialize)]
struct SourceSection {
    kind: String,
    repository: String,
}

#[derive(Debug, Deserialize)]
struct BuildSection {
    command: String,
    #[serde(default)]
    outputs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SemverTag {
    major: u64,
    minor: u64,
    patch: u64,
    tag: String,
}

pub(crate) fn parse_github_install_url(input: &str) -> Result<Option<GitHubRepo>> {
    if is_raw_remote_wasm(input) {
        bail!(
            "raw remote .wasm installs are not supported; install a trusted Petal source repository"
        );
    }

    if let Some(rest) = input.strip_prefix("git@github.com:") {
        let (owner, repo) = split_owner_repo(rest)?;
        return trusted_repo(owner, repo).map(Some);
    }

    if input.contains("://") {
        let url = Url::parse(input).with_context(|| format!("parse GitHub source URL {input}"))?;
        if url.host_str() != Some("github.com") {
            bail!(
                "unsupported GitHub source host {}; only github.com is supported",
                url.host_str().unwrap_or("<missing>")
            );
        }
        let mut segments = url
            .path_segments()
            .ok_or_else(|| anyhow!("GitHub source URL is missing owner/repo path"))?;
        let owner = segments
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("GitHub source URL is missing owner"))?;
        let repo = segments
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("GitHub source URL is missing repo"))?;
        if segments.next().is_some() {
            bail!("GitHub Petal source URLs must point at a repository root");
        }
        return trusted_repo(owner, repo).map(Some);
    }

    Ok(None)
}

pub(crate) fn install_github_source(
    home: &HomeDir,
    daemon: &Daemon,
    repo: &GitHubRepo,
    requested_ref: Option<&str>,
) -> Result<GitHubInstallOutput> {
    install_github_source_with_expectation(home, daemon, repo, requested_ref, None)
}

fn install_github_source_with_expectation(
    home: &HomeDir,
    daemon: &Daemon,
    repo: &GitHubRepo,
    requested_ref: Option<&str>,
    expected: Option<&PreinstalledPetal>,
) -> Result<GitHubInstallOutput> {
    println!("Resolving {}", repo.canonical_url);
    let cache = fetch_repo_cache(home, repo)?;
    let resolved = resolve_ref(&cache, repo, requested_ref)?;
    if let Some(expected) = expected
        && resolved.commit != expected.commit
    {
        bail!(
            "pre-installed Petal {} resolved commit {} does not match pinned commit {}",
            expected.name,
            resolved.commit,
            expected.commit
        );
    }
    if let Some(tag) = &resolved.selected_tag {
        println!("Selected tag: {tag}");
    }
    println!("Resolved commit: {}", resolved.commit);

    let tmp = tempfile::tempdir().context("create source checkout tempdir")?;
    checkout_source(&cache, tmp.path(), &resolved.commit)?;
    validate_source_manifest(tmp.path(), repo)?;

    println!("Building source package...");
    run_source_build(tmp.path())?;

    println!("Validating Petal package...");
    let package =
        PreparedPetalPackage::from_dir(tmp.path()).context("validate generated Petal package")?;
    if let Some(expected) = expected {
        if package.name != expected.name {
            bail!(
                "pre-installed Petal {} built unexpected package name {:?}",
                expected.name,
                package.name
            );
        }
        if let Some(expected_hash) = expected.expected_hash
            && package.hash != expected_hash
        {
            bail!(
                "pre-installed Petal {} package hash {} does not match expected hash {}",
                expected.name,
                package.hash,
                expected_hash
            );
        }
    }
    let mut consent = petal_consent_summary(&package).context("build app consent summary")?;
    let bindings = daemon
        .config
        .petals
        .runtime
        .get(&consent.name)
        .map(|app| &app.endpoints)
        .cloned()
        .unwrap_or_default();
    bloom_petals::package::apply_petal_consent_endpoint_bindings(&mut consent, &bindings)
        .context("apply configured Petal endpoint bindings")?;
    let provenance = PetalSourceProvenance {
        source_kind: "github".to_string(),
        url: repo.canonical_url.clone(),
        owner: repo.owner.clone(),
        repo: repo.repo.clone(),
        requested_ref: resolved.requested_ref.clone(),
        resolved_commit: resolved.commit.clone(),
        selected_tag: resolved.selected_tag.clone(),
        package_hash: package.hash.clone(),
    };
    let (result, meta, index) = daemon
        .petals
        .store()
        .install_prepared_petal_package_with_source(package, Some(provenance.clone()))
        .context("install generated Petal package")?;

    Ok(GitHubInstallOutput {
        result,
        meta,
        index,
        consent,
        provenance,
    })
}

pub(crate) fn ensure_preinstalled_petals(home: &HomeDir, daemon: &Daemon) -> Result<Vec<String>> {
    let owners = daemon
        .petals
        .store()
        .list_petal_owners()
        .context("list installed Petal owners before provisioning")?;
    let owners = owners
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut ready = Vec::new();

    for name in &daemon.config.petals.preinstalled {
        let entry = preinstalled_petal(name)
            .ok_or_else(|| anyhow!("unknown pre-installed Petal {name:?}"))?;
        if let Some(hash) = owners.get(name) {
            let meta = daemon.petals.store().load_meta(hash).with_context(|| {
                format!("load installed metadata for pre-installed Petal {name}")
            })?;
            validate_existing_preinstalled(entry, &meta)?;
            println!(
                "preinstalled_petal: {name} (already installed at {})",
                &hash[..hash.len().min(bloom_petals::store::HASH_PREFIX_LEN)]
            );
            ready.push(name.clone());
            continue;
        }

        println!(
            "preinstalled_petal: installing {} from {}@{}",
            entry.name, entry.repository, entry.commit
        );
        let repo = parse_github_install_url(entry.repository)?
            .ok_or_else(|| anyhow!("built-in Petal repository is not a GitHub source URL"))?;
        let installed = install_github_source_with_expectation(
            home,
            daemon,
            &repo,
            Some(entry.commit),
            Some(entry),
        )
        .with_context(|| {
            format!(
                "provision pre-installed Petal {} from {}@{}; fix the cause and retry `bloom init`, or persistently opt out with `[petals] preinstalled = []`",
                entry.name, entry.repository, entry.commit
            )
        })?;
        validate_existing_preinstalled(entry, &installed.meta)?;
        println!(
            "preinstalled_petal: {} ready at petals/{}/",
            entry.name, entry.name
        );
        ready.push(name.clone());
    }

    Ok(ready)
}

fn preinstalled_petal(name: &str) -> Option<&'static PreinstalledPetal> {
    match name {
        "polymarket" => Some(&PREINSTALLED_POLYMARKET),
        _ => None,
    }
}

fn validate_existing_preinstalled(
    expected: &PreinstalledPetal,
    meta: &bloom_petals::meta::PetalMeta,
) -> Result<()> {
    let package = meta
        .petal
        .as_ref()
        .ok_or_else(|| anyhow!("installed owner {} is not a Petal package", expected.name))?;
    if package.name != expected.name {
        bail!(
            "installed owner {} reports unexpected package name {:?}",
            expected.name,
            package.name
        );
    }
    let source = meta.source.as_ref().ok_or_else(|| {
        anyhow!(
            "pre-installed Petal {} is already owned by an installation without source provenance; uninstall it or set `[petals] preinstalled = []`",
            expected.name
        )
    })?;
    let expected_repo = expected
        .repository
        .strip_prefix("https://github.com/")
        .unwrap_or(expected.repository);
    let actual_repo = format!("{}/{}", source.owner, source.repo);
    if source.source_kind != "github"
        || actual_repo != expected_repo
        || source.resolved_commit != expected.commit
    {
        bail!(
            "pre-installed Petal {} is already owned by {}@{} instead of {}@{}; Bloom will not overwrite it automatically",
            expected.name,
            actual_repo,
            source.resolved_commit,
            expected_repo,
            expected.commit
        );
    }
    if source.package_hash != meta.hash {
        bail!(
            "pre-installed Petal {} source provenance hash {} does not match installed hash {}",
            expected.name,
            source.package_hash,
            meta.hash
        );
    }
    if let Some(expected_hash) = expected.expected_hash
        && meta.hash != expected_hash
    {
        bail!(
            "pre-installed Petal {} hash {} does not match expected hash {}",
            expected.name,
            meta.hash,
            expected_hash
        );
    }
    Ok(())
}

fn is_raw_remote_wasm(input: &str) -> bool {
    (input.starts_with("http://")
        || input.starts_with("https://")
        || input.starts_with("git@")
        || input.starts_with("ssh://"))
        && input
            .split(['?', '#'])
            .next()
            .is_some_and(|path| path.ends_with(".wasm"))
}

fn split_owner_repo(path: &str) -> Result<(&str, &str)> {
    let path = path.strip_suffix(".git").unwrap_or(path);
    let mut segments = path.split('/');
    let owner = segments
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("GitHub source URL is missing owner"))?;
    let repo = segments
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("GitHub source URL is missing repo"))?;
    if segments.next().is_some() {
        bail!("GitHub Petal source URLs must point at a repository root");
    }
    Ok((owner, repo))
}

fn trusted_repo(owner: &str, repo: &str) -> Result<GitHubRepo> {
    if owner != TRUSTED_GITHUB_OWNER {
        bail!("unsupported GitHub owner {owner}; trusted owner is {TRUSTED_GITHUB_OWNER}");
    }
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    if repo.is_empty() || repo.contains('/') {
        bail!("GitHub source URL has invalid repository name");
    }
    Ok(GitHubRepo {
        owner: owner.to_string(),
        repo: repo.to_string(),
        canonical_url: format!("https://github.com/{owner}/{repo}"),
        clone_url: format!("https://github.com/{owner}/{repo}.git"),
    })
}

fn fetch_repo_cache(home: &HomeDir, repo: &GitHubRepo) -> Result<PathBuf> {
    let cache = home
        .root()
        .join("petals")
        .join("source-cache")
        .join("github")
        .join(&repo.owner)
        .join(format!("{}.git", repo.repo));
    if cache.exists() {
        git(
            Some(&cache),
            &[
                "fetch",
                "--prune",
                "--tags",
                "origin",
                "+refs/heads/*:refs/remotes/origin/*",
                "+refs/tags/*:refs/tags/*",
            ],
        )
        .with_context(|| format!("fetch GitHub source cache {}", cache.display()))?;
    } else {
        let parent = cache
            .parent()
            .ok_or_else(|| anyhow!("source cache path has no parent"))?;
        std::fs::create_dir_all(parent)?;
        let cache_arg = cache.to_string_lossy().to_string();
        git(
            None,
            &["clone", "--bare", "--quiet", &repo.clone_url, &cache_arg],
        )
        .with_context(|| format!("clone GitHub source {}", repo.canonical_url))?;
    }
    Ok(cache)
}

#[derive(Debug)]
struct ResolvedRef {
    requested_ref: String,
    commit: String,
    selected_tag: Option<String>,
}

fn resolve_ref(
    cache: &Path,
    repo: &GitHubRepo,
    requested_ref: Option<&str>,
) -> Result<ResolvedRef> {
    if let Some(requested_ref) = requested_ref {
        let commit = resolve_explicit_ref(cache, requested_ref).with_context(|| {
            format!(
                "GitHub Petal ref {requested_ref:?} was not found in {}",
                repo.canonical_url
            )
        })?;
        let selected_tag = explicit_tag_commit(cache, requested_ref)
            .ok()
            .filter(|tag_commit| tag_commit == &commit)
            .map(|_| requested_ref.to_string());
        return Ok(ResolvedRef {
            requested_ref: requested_ref.to_string(),
            commit,
            selected_tag,
        });
    }

    let tags = git_stdout(Some(cache), &["tag", "--list"])?;
    let selected = latest_semver_tag(tags.lines()).ok_or_else(|| {
        anyhow!(
            "no SemVer tags found for {}; pass --ref <branch-or-sha> or publish a tag",
            repo.canonical_url
        )
    })?;
    let commit = resolve_explicit_ref(cache, &selected.tag)?;
    Ok(ResolvedRef {
        requested_ref: selected.tag.clone(),
        commit,
        selected_tag: Some(selected.tag),
    })
}

fn resolve_explicit_ref(cache: &Path, requested_ref: &str) -> Result<String> {
    let mut candidates = Vec::with_capacity(4);
    if is_full_commit_id(requested_ref) {
        candidates.push(requested_ref.to_string());
    }
    candidates.extend([
        format!("refs/tags/{requested_ref}"),
        format!("refs/remotes/origin/{requested_ref}"),
        requested_ref.to_string(),
    ]);

    for candidate in candidates {
        let rev = format!("{candidate}^{{commit}}");
        if let Ok(commit) = git_stdout(Some(cache), &["rev-parse", "--verify", "--quiet", &rev]) {
            let commit = commit.trim().to_string();
            if !commit.is_empty() {
                return Ok(commit);
            }
        }
    }
    bail!("ref not found")
}

fn is_full_commit_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn explicit_tag_commit(cache: &Path, requested_ref: &str) -> Result<String> {
    let rev = format!("refs/tags/{requested_ref}^{{commit}}");
    let commit = git_stdout(Some(cache), &["rev-parse", "--verify", "--quiet", &rev])?;
    let commit = commit.trim().to_string();
    if commit.is_empty() {
        bail!("tag not found")
    }
    Ok(commit)
}

fn checkout_source(cache: &Path, root: &Path, commit: &str) -> Result<()> {
    let cache_arg = cache.to_string_lossy().to_string();
    let root_arg = root.to_string_lossy().to_string();
    git(None, &["clone", "--quiet", &cache_arg, &root_arg]).context("clone cached source")?;
    git(Some(root), &["checkout", "--quiet", "--detach", commit]).context("checkout source ref")?;
    Ok(())
}

fn validate_source_manifest(root: &Path, repo: &GitHubRepo) -> Result<()> {
    let manifest = read_source_manifest(root)?;
    if manifest.schema.as_deref() != Some("bloom.petal.package.v1") {
        bail!("GitHub Petal source must declare schema = \"bloom.petal.package.v1\"");
    }
    let source = manifest
        .source
        .as_ref()
        .ok_or_else(|| anyhow!("GitHub Petal source petal.toml is missing [source]"))?;
    if source.kind != "github" {
        bail!("GitHub Petal source petal.toml must set [source] kind = \"github\"");
    }
    let expected = format!("{}/{}", repo.owner, repo.repo);
    if source.repository != expected {
        bail!(
            "GitHub Petal source repository mismatch: petal.toml declares {}, URL is {}",
            source.repository,
            expected
        );
    }
    if manifest.build.is_none() {
        bail!("GitHub Petal source petal.toml is missing [build] command");
    }
    Ok(())
}

fn run_source_build(root: &Path) -> Result<()> {
    let manifest = read_source_manifest(root)?;
    let build = manifest
        .build
        .ok_or_else(|| anyhow!("GitHub Petal source petal.toml is missing [build] command"))?;
    validate_repo_relative_path(&build.command, "build.command")?;
    let command = root.join(&build.command);
    if !command.is_file() {
        bail!("build command missing: {}", build.command);
    }
    let status = Command::new(&command)
        .current_dir(root)
        .status()
        .with_context(|| format!("run build command {}", build.command))?;
    if !status.success() {
        bail!("build command failed: {}", build.command);
    }
    for output in build.outputs {
        validate_repo_relative_path(&output, "build.outputs")?;
        if !root.join(&output).is_dir() {
            bail!("build output missing: {output}");
        }
    }
    Ok(())
}

fn read_source_manifest(root: &Path) -> Result<SourcePetalToml> {
    let petal_toml = root.join("petal.toml");
    let body = std::fs::read_to_string(&petal_toml)
        .with_context(|| format!("read {}", petal_toml.display()))?;
    toml::from_str(&body).context("parse source petal.toml")
}

fn validate_repo_relative_path(path: &str, field: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.bytes().any(|b| b == 0)
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        bail!("{field} must be a repository-relative path");
    }
    Ok(())
}

fn latest_semver_tag<'a>(tags: impl Iterator<Item = &'a str>) -> Option<SemverTag> {
    tags.filter_map(parse_semver_tag).max()
}

fn parse_semver_tag(tag: &str) -> Option<SemverTag> {
    let version = tag.strip_prefix('v').unwrap_or(tag);
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(SemverTag {
        major,
        minor,
        patch,
        tag: tag.to_string(),
    })
}

fn git(cwd: Option<&Path>, args: &[&str]) -> Result<()> {
    let output = git_output(cwd, args)?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn git_stdout(cwd: Option<&Path>, args: &[&str]) -> Result<String> {
    let output = git_output(cwd, args)?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn git_output(cwd: Option<&Path>, args: &[&str]) -> Result<std::process::Output> {
    let mut command = Command::new("git");
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.args(args);
    command.output().context("spawn git")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_petals::meta::{PetalMeta, PetalMode, PetalPackageMeta, PetalSourceProvenance};
    use bloom_proto::HomeDir;
    use bloom_vfs::VfsPath;
    use bloom_vfs::handler::Handler;
    use tempfile::TempDir;

    #[test]
    fn parses_supported_github_urls() {
        for raw in [
            "https://github.com/bloom-directory/bloom-petal-polymarket",
            "https://github.com/bloom-directory/bloom-petal-polymarket.git",
            "git@github.com:bloom-directory/bloom-petal-polymarket.git",
        ] {
            let parsed = parse_github_install_url(raw).unwrap().unwrap();
            assert_eq!(parsed.owner, "bloom-directory");
            assert_eq!(parsed.repo, "bloom-petal-polymarket");
            assert_eq!(
                parsed.canonical_url,
                "https://github.com/bloom-directory/bloom-petal-polymarket"
            );
            assert_eq!(
                parsed.clone_url,
                "https://github.com/bloom-directory/bloom-petal-polymarket.git"
            );
        }
    }

    #[test]
    fn rejects_untrusted_owner_and_raw_wasm() {
        let err = parse_github_install_url("https://github.com/other/petal")
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsupported GitHub owner"));

        let err =
            parse_github_install_url("https://github.com/bloom-directory/petal/raw/main/a.wasm")
                .unwrap_err()
                .to_string();
        assert!(err.contains("raw remote .wasm"));
    }

    #[test]
    fn selects_latest_semver_like_tag() {
        let latest = latest_semver_tag(["v0.1.0", "v0.10.0", "junk", "0.2.1"].into_iter()).unwrap();
        assert_eq!(latest.tag, "v0.10.0");
    }

    #[test]
    fn built_in_polymarket_entry_is_immutable_and_catalogued() {
        let entry = preinstalled_petal("polymarket").unwrap();
        assert_eq!(entry.name, "polymarket");
        assert_eq!(entry.commit.len(), 40);
        assert!(entry.commit.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(entry.repository.ends_with("/bloom-petal-polymarket"));
        assert!(preinstalled_petal("unknown").is_none());
    }

    #[test]
    fn existing_preinstalled_package_must_match_source_commit_and_hash() {
        let entry = preinstalled_petal("polymarket").unwrap();
        let hash = "a".repeat(64);
        let mut meta = PetalMeta {
            hash: hash.clone(),
            size: 1,
            installed_at_ms: 1,
            name: Some("polymarket".into()),
            caps: Default::default(),
            mode: PetalMode::Local,
            petal: Some(PetalPackageMeta {
                name: "polymarket".into(),
                petal_root: "polymarket".into(),
                route_index_schema: "test".into(),
            }),
            source: Some(PetalSourceProvenance {
                source_kind: "github".into(),
                url: entry.repository.into(),
                owner: "bloom-directory".into(),
                repo: "bloom-petal-polymarket".into(),
                requested_ref: entry.commit.into(),
                resolved_commit: entry.commit.into(),
                selected_tag: None,
                package_hash: hash,
            }),
        };
        validate_existing_preinstalled(entry, &meta).unwrap();

        meta.source.as_mut().unwrap().resolved_commit = "b".repeat(40);
        let err = validate_existing_preinstalled(entry, &meta)
            .unwrap_err()
            .to_string();
        assert!(err.contains("will not overwrite it automatically"), "{err}");

        meta.source.as_mut().unwrap().resolved_commit = entry.commit.into();
        meta.source.as_mut().unwrap().package_hash = "c".repeat(64);
        let err = validate_existing_preinstalled(entry, &meta)
            .unwrap_err()
            .to_string();
        assert!(err.contains("provenance hash"), "{err}");
    }

    #[test]
    fn explicit_empty_preinstalled_list_is_network_free_and_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let home_dir = HomeDir::at(home.path());
        let mut config = bloom_proto::Config::local_default();
        config.petals.preinstalled.clear();
        config.save(&home_dir.config_path()).unwrap();
        let daemon = Daemon::from_home(home_dir.clone()).unwrap();

        assert!(
            ensure_preinstalled_petals(&home_dir, &daemon)
                .unwrap()
                .is_empty()
        );
        assert!(
            ensure_preinstalled_petals(&home_dir, &daemon)
                .unwrap()
                .is_empty()
        );
        assert!(
            daemon
                .petals
                .store()
                .list_petal_owners()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn resolves_latest_semver_tag_by_default() {
        let fixture = git_fixture(&["v0.1.0", "v0.1.1"]).unwrap();
        let repo = test_repo();
        let resolved = resolve_ref(fixture.bare.path(), &repo, None).unwrap();
        assert_eq!(resolved.requested_ref, "v0.1.1");
        assert_eq!(resolved.selected_tag.as_deref(), Some("v0.1.1"));
        assert_eq!(resolved.commit, fixture.commits[1]);
    }

    #[test]
    fn resolves_explicit_tag_branch_and_sha() {
        let fixture = git_fixture(&["v0.1.0"]).unwrap();
        let repo = test_repo();

        let tag = resolve_ref(fixture.bare.path(), &repo, Some("v0.1.0")).unwrap();
        assert_eq!(tag.selected_tag.as_deref(), Some("v0.1.0"));
        assert_eq!(tag.commit, fixture.commits[0]);

        let branch = resolve_ref(fixture.bare.path(), &repo, Some("main")).unwrap();
        assert_eq!(branch.selected_tag, None);
        assert_eq!(branch.commit, fixture.commits[1]);

        let sha = resolve_ref(fixture.bare.path(), &repo, Some(&fixture.commits[0])).unwrap();
        assert_eq!(sha.selected_tag, None);
        assert_eq!(sha.commit, fixture.commits[0]);
    }

    #[test]
    fn resolves_explicit_branch_from_freshly_fetched_origin_ref() {
        let work = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        test_git(Some(work.path()), &["init", "-b", "main"]).unwrap();
        test_git(
            Some(work.path()),
            &["config", "user.email", "test@example.com"],
        )
        .unwrap();
        test_git(Some(work.path()), &["config", "user.name", "Test User"]).unwrap();
        test_git(Some(remote.path()), &["init", "--bare"]).unwrap();
        let remote_path = remote.path().to_string_lossy().to_string();
        test_git(
            Some(work.path()),
            &["remote", "add", "origin", &remote_path],
        )
        .unwrap();

        std::fs::write(work.path().join("file.txt"), "one").unwrap();
        test_git(Some(work.path()), &["add", "file.txt"]).unwrap();
        test_git(Some(work.path()), &["commit", "-m", "one"]).unwrap();
        let first = test_git_stdout(Some(work.path()), &["rev-parse", "HEAD"])
            .unwrap()
            .trim()
            .to_string();
        test_git(Some(work.path()), &["push", "origin", "main"]).unwrap();

        let repo = source_test_repo(remote.path(), "bloom-petal-test-advancing");
        let home_dir = HomeDir::at(home.path());
        let cache = fetch_repo_cache(&home_dir, &repo).unwrap();
        assert_eq!(
            test_git_stdout(Some(&cache), &["rev-parse", "refs/heads/main"])
                .unwrap()
                .trim(),
            first
        );

        std::fs::write(work.path().join("file.txt"), "two").unwrap();
        test_git(Some(work.path()), &["commit", "-am", "two"]).unwrap();
        let second = test_git_stdout(Some(work.path()), &["rev-parse", "HEAD"])
            .unwrap()
            .trim()
            .to_string();
        test_git(Some(work.path()), &["push", "origin", "main"]).unwrap();

        let cache = fetch_repo_cache(&home_dir, &repo).unwrap();
        assert_eq!(
            test_git_stdout(Some(&cache), &["rev-parse", "refs/heads/main"])
                .unwrap()
                .trim(),
            first,
            "the bare clone's local branch demonstrates the stale-cache condition"
        );
        assert_eq!(
            test_git_stdout(Some(&cache), &["rev-parse", "refs/remotes/origin/main"])
                .unwrap()
                .trim(),
            second
        );

        let resolved = resolve_ref(&cache, &repo, Some("main")).unwrap();
        assert_eq!(resolved.commit, second);
    }

    #[test]
    fn explicit_unknown_ref_does_not_match_a_similarly_named_ref() {
        let fixture = git_fixture(&["v0.1.0"]).unwrap();
        let error = resolve_ref(fixture.bare.path(), &test_repo(), Some("mai"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("ref \"mai\" was not found"));
    }

    #[test]
    fn default_resolution_fails_without_semver_tags() {
        let fixture = git_fixture(&[]).unwrap();
        let repo = test_repo();
        let err = resolve_ref(fixture.bare.path(), &repo, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no SemVer tags found"));
        assert!(err.contains("pass --ref"));
    }

    #[test]
    fn source_install_from_local_bare_repo_uses_latest_tag_records_provenance_and_dispatches() {
        let fixture = source_repo_fixture(SourceRepoOptions {
            repo: "bloom-petal-test-latest",
            tags: vec!["v0.1.0", "v0.1.1"],
            include_manifest: true,
            build_script: BuildScript::Success,
        })
        .unwrap();
        let repo = source_test_repo(fixture.bare.path(), "bloom-petal-test-latest");
        let home = tempfile::tempdir().unwrap();
        let home_dir = HomeDir::at(home.path());
        let daemon = Daemon::from_home(home_dir.clone()).unwrap();

        let installed = install_github_source(&home_dir, &daemon, &repo, None).unwrap();

        assert_eq!(installed.provenance.selected_tag.as_deref(), Some("v0.1.1"));
        assert_eq!(installed.provenance.requested_ref, "v0.1.1");
        assert_eq!(installed.provenance.resolved_commit, fixture.commits[1]);
        assert_eq!(installed.index.petal_root, "demo");
        assert_eq!(installed.index.routes.len(), 1);
        let loaded = daemon
            .petals
            .store()
            .load_meta(&installed.result.hash)
            .unwrap();
        assert_eq!(loaded.source.as_ref(), Some(&installed.provenance));

        let rt = tokio::runtime::Runtime::new().unwrap();
        let body = rt
            .block_on(
                daemon
                    .vfs
                    .read(&VfsPath::parse("/petals/demo/hello.txt").unwrap()),
            )
            .unwrap();
        assert_eq!(body, b"component");
    }

    #[test]
    fn source_install_honors_explicit_tag_and_sha_refs() {
        let fixture = source_repo_fixture(SourceRepoOptions {
            repo: "bloom-petal-test-ref",
            tags: vec!["v0.1.0", "v0.1.1"],
            include_manifest: true,
            build_script: BuildScript::Success,
        })
        .unwrap();
        let repo = source_test_repo(fixture.bare.path(), "bloom-petal-test-ref");

        let tag_home = tempfile::tempdir().unwrap();
        let tag_home_dir = HomeDir::at(tag_home.path());
        let tag_daemon = Daemon::from_home(tag_home_dir.clone()).unwrap();
        let tag_install =
            install_github_source(&tag_home_dir, &tag_daemon, &repo, Some("v0.1.0")).unwrap();
        assert_eq!(
            tag_install.provenance.selected_tag.as_deref(),
            Some("v0.1.0")
        );
        assert_eq!(tag_install.provenance.resolved_commit, fixture.commits[0]);

        let sha_home = tempfile::tempdir().unwrap();
        let sha_home_dir = HomeDir::at(sha_home.path());
        let sha_daemon = Daemon::from_home(sha_home_dir.clone()).unwrap();
        let sha_install =
            install_github_source(&sha_home_dir, &sha_daemon, &repo, Some(&fixture.commits[0]))
                .unwrap();
        assert_eq!(sha_install.provenance.selected_tag, None);
        assert_eq!(sha_install.provenance.requested_ref, fixture.commits[0]);
        assert_eq!(sha_install.provenance.resolved_commit, fixture.commits[0]);
    }

    #[test]
    fn source_install_rejects_invalid_endpoint_binding_before_installing_package() {
        let fixture = source_repo_fixture(SourceRepoOptions {
            repo: "bloom-petal-test-endpoint",
            tags: vec!["v0.1.0"],
            include_manifest: true,
            build_script: BuildScript::Success,
        })
        .unwrap();
        let repo = source_test_repo(fixture.bare.path(), "bloom-petal-test-endpoint");
        let home = tempfile::tempdir().unwrap();
        let home_dir = HomeDir::at(home.path());
        home_dir.ensure().unwrap();
        let mut config = bloom_proto::Config::local_default();
        config.petals.runtime.insert(
            "demo".into(),
            bloom_proto::config::PetalRuntimeConfig {
                endpoints: std::collections::BTreeMap::from([(
                    "undeclared".into(),
                    "https://example.com".into(),
                )]),
                values: Default::default(),
            },
        );
        config.save(&home_dir.config_path()).unwrap();
        let daemon = Daemon::from_home(home_dir.clone()).unwrap();

        let err = install_github_source(&home_dir, &daemon, &repo, None).unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("endpoint override \"undeclared\" is not declared"));
        assert!(
            daemon
                .petals
                .store()
                .list_package_hashes()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn source_install_rejects_no_tags_missing_manifest_and_preserves_existing_state_on_build_failure()
     {
        let good = source_repo_fixture(SourceRepoOptions {
            repo: "bloom-petal-test-good",
            tags: vec!["v0.1.0"],
            include_manifest: true,
            build_script: BuildScript::Success,
        })
        .unwrap();
        let no_tags = source_repo_fixture(SourceRepoOptions {
            repo: "bloom-petal-test-no-tags",
            tags: vec![],
            include_manifest: true,
            build_script: BuildScript::Success,
        })
        .unwrap();
        let missing_manifest = source_repo_fixture(SourceRepoOptions {
            repo: "bloom-petal-test-missing-manifest",
            tags: vec!["v0.1.0"],
            include_manifest: false,
            build_script: BuildScript::Success,
        })
        .unwrap();
        let failing = source_repo_fixture(SourceRepoOptions {
            repo: "bloom-petal-test-failing",
            tags: vec!["v0.1.0"],
            include_manifest: true,
            build_script: BuildScript::Failure,
        })
        .unwrap();

        let home = tempfile::tempdir().unwrap();
        let home_dir = HomeDir::at(home.path());
        let daemon = Daemon::from_home(home_dir.clone()).unwrap();

        let good_install = install_github_source(
            &home_dir,
            &daemon,
            &source_test_repo(good.bare.path(), "bloom-petal-test-good"),
            None,
        )
        .unwrap();
        let before = daemon.petals.store().list_package_hashes().unwrap();
        assert_eq!(before, vec![good_install.result.hash.clone()]);

        let no_tag_err = install_github_source(
            &home_dir,
            &daemon,
            &source_test_repo(no_tags.bare.path(), "bloom-petal-test-no-tags"),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(no_tag_err.contains("no SemVer tags found"));

        let manifest_err = install_github_source(
            &home_dir,
            &daemon,
            &source_test_repo(
                missing_manifest.bare.path(),
                "bloom-petal-test-missing-manifest",
            ),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(manifest_err.contains("petal.toml"));

        let build_err = install_github_source(
            &home_dir,
            &daemon,
            &source_test_repo(failing.bare.path(), "bloom-petal-test-failing"),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(build_err.contains("build command failed"));

        let after = daemon.petals.store().list_package_hashes().unwrap();
        assert_eq!(after, before);
    }

    struct GitFixture {
        _work: TempDir,
        bare: TempDir,
        commits: Vec<String>,
    }

    fn git_fixture(tags: &[&str]) -> Result<GitFixture> {
        let work = tempfile::tempdir()?;
        let bare = tempfile::tempdir()?;
        test_git(Some(work.path()), &["init", "-b", "main"])?;
        test_git(
            Some(work.path()),
            &["config", "user.email", "test@example.com"],
        )?;
        test_git(Some(work.path()), &["config", "user.name", "Test User"])?;

        std::fs::write(work.path().join("file.txt"), "one")?;
        test_git(Some(work.path()), &["add", "file.txt"])?;
        test_git(Some(work.path()), &["commit", "-m", "one"])?;
        let first = test_git_stdout(Some(work.path()), &["rev-parse", "HEAD"])?;
        for tag in tags {
            if *tag == "v0.1.0" {
                test_git(Some(work.path()), &["tag", tag])?;
            }
        }

        std::fs::write(work.path().join("file.txt"), "two")?;
        test_git(Some(work.path()), &["commit", "-am", "two"])?;
        let second = test_git_stdout(Some(work.path()), &["rev-parse", "HEAD"])?;
        for tag in tags {
            if *tag != "v0.1.0" {
                test_git(Some(work.path()), &["tag", tag])?;
            }
        }

        test_git(Some(bare.path()), &["init", "--bare"])?;
        let bare_remote = bare.path().to_string_lossy().to_string();
        test_git(
            Some(work.path()),
            &["remote", "add", "origin", &bare_remote],
        )?;
        test_git(Some(work.path()), &["push", "--tags", "origin", "main"])?;

        Ok(GitFixture {
            _work: work,
            bare,
            commits: vec![first.trim().to_string(), second.trim().to_string()],
        })
    }

    fn test_repo() -> GitHubRepo {
        GitHubRepo {
            owner: "bloom-directory".to_string(),
            repo: "bloom-petal-test".to_string(),
            canonical_url: "https://github.com/bloom-directory/bloom-petal-test".to_string(),
            clone_url: "https://github.com/bloom-directory/bloom-petal-test.git".to_string(),
        }
    }

    struct SourceRepoOptions {
        repo: &'static str,
        tags: Vec<&'static str>,
        include_manifest: bool,
        build_script: BuildScript,
    }

    enum BuildScript {
        Success,
        Failure,
    }

    fn source_repo_fixture(options: SourceRepoOptions) -> Result<GitFixture> {
        let work = tempfile::tempdir()?;
        let bare = tempfile::tempdir()?;
        test_git(Some(work.path()), &["init", "-b", "main"])?;
        test_git(
            Some(work.path()),
            &["config", "user.email", "test@example.com"],
        )?;
        test_git(Some(work.path()), &["config", "user.name", "Test User"])?;

        write_source_repo(
            &work,
            options.repo,
            options.include_manifest,
            &options.build_script,
            "one",
        )?;
        test_git(Some(work.path()), &["add", "."])?;
        test_git(Some(work.path()), &["commit", "-m", "one"])?;
        let first = test_git_stdout(Some(work.path()), &["rev-parse", "HEAD"])?;
        for tag in &options.tags {
            if *tag == "v0.1.0" {
                test_git(Some(work.path()), &["tag", tag])?;
            }
        }

        std::fs::write(work.path().join("README.md"), b"# demo Petal\n")?;
        test_git(Some(work.path()), &["commit", "-am", "two"])?;
        let second = test_git_stdout(Some(work.path()), &["rev-parse", "HEAD"])?;
        for tag in &options.tags {
            if *tag != "v0.1.0" {
                test_git(Some(work.path()), &["tag", tag])?;
            }
        }

        test_git(Some(bare.path()), &["init", "--bare"])?;
        let bare_remote = bare.path().to_string_lossy().to_string();
        test_git(
            Some(work.path()),
            &["remote", "add", "origin", &bare_remote],
        )?;
        test_git(Some(work.path()), &["push", "--tags", "origin", "main"])?;

        Ok(GitFixture {
            _work: work,
            bare,
            commits: vec![first.trim().to_string(), second.trim().to_string()],
        })
    }

    fn write_source_repo(
        work: &TempDir,
        repo: &str,
        include_manifest: bool,
        build_script: &BuildScript,
        readme_suffix: &str,
    ) -> Result<()> {
        if include_manifest {
            let manifest = r#"schema = "bloom.petal.package.v1"
name = "demo"

[source]
kind = "github"
repository = "bloom-directory/REPO_NAME"

[build]
command = "scripts/build.sh"
outputs = ["petal/demo"]

[consent]
summary = "Demo app used by source install tests."
"#
            .replace("REPO_NAME", repo);
            std::fs::write(work.path().join("petal.toml"), manifest)?;
        }
        std::fs::write(
            work.path().join("README.md"),
            format!("# demo {readme_suffix}\n"),
        )?;
        std::fs::write(work.path().join("AGENTS.md"), b"# demo agents\n")?;
        std::fs::create_dir_all(work.path().join("components"))?;
        std::fs::write(
            work.path().join("components/route.wasm"),
            include_bytes!("../../bloom-petals/tests/fixtures/route_component_no_imports.wasm"),
        )?;
        std::fs::create_dir_all(work.path().join("scripts"))?;
        let script = match build_script {
            BuildScript::Success => {
                "#!/usr/bin/env bash\nset -euo pipefail\nmkdir -p petal/demo\ncp components/route.wasm petal/demo/hello.txt.wasm\n"
            }
            BuildScript::Failure => "#!/usr/bin/env bash\nset -euo pipefail\nexit 42\n",
        };
        let script_path = work.path().join("scripts/build.sh");
        std::fs::write(&script_path, script)?;
        make_executable(&script_path)?;
        Ok(())
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions)?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) -> Result<()> {
        Ok(())
    }

    fn source_test_repo(bare: &Path, repo: &str) -> GitHubRepo {
        GitHubRepo {
            owner: "bloom-directory".to_string(),
            repo: repo.to_string(),
            canonical_url: format!("https://github.com/bloom-directory/{repo}"),
            clone_url: bare.to_string_lossy().to_string(),
        }
    }

    fn test_git(cwd: Option<&Path>, args: &[&str]) -> Result<()> {
        let output = test_git_output(cwd, args)?;
        if output.status.success() {
            return Ok(());
        }
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }

    fn test_git_stdout(cwd: Option<&Path>, args: &[&str]) -> Result<String> {
        let output = test_git_output(cwd, args)?;
        if !output.status.success() {
            bail!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn test_git_output(cwd: Option<&Path>, args: &[&str]) -> Result<std::process::Output> {
        let mut command = Command::new("git");
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        command.args(args);
        command.output().context("spawn test git")
    }
}
