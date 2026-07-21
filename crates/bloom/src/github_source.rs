use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use bloom_daemon::Daemon;
use bloom_petals::meta::PetalSourceProvenance;
use bloom_petals::package::{
    PetalConsentSummary, PreparedPetalPackage, RouteIndex, petal_consent_summary,
};
use bloom_proto::HomeDir;
use flate2::read::GzDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

const TRUSTED_GITHUB_OWNER: &str = "bloom-directory";
const POLYMARKET_PARITY_COMMIT: &str = "e2e898b69046c9f5d905dd2cd66b3a57ef195542";
const NEAR_INTENTS_INITIAL_RELEASE_COMMIT: &str = "320b2b466bc0eb087a5cae3e658a5797198ce8ba";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreinstalledPetal {
    pub name: &'static str,
    pub repository: &'static str,
    pub commit: &'static str,
    pub release_tag: &'static str,
    pub archive: &'static str,
    pub expected_hash: Option<&'static str>,
}

const PREINSTALLED_POLYMARKET: PreinstalledPetal = PreinstalledPetal {
    name: "polymarket",
    repository: "https://github.com/bloom-directory/bloom-petal-polymarket",
    commit: POLYMARKET_PARITY_COMMIT,
    release_tag: "v0.1.3",
    archive: "polymarket-v0.1.3.petal.tar.gz",
    expected_hash: Some("02d6d18d773147013c3b1e7129c4694d2db3c93f1e885e755bdb4aa390bf6a5c"),
};

const PREINSTALLED_NEAR_INTENTS: PreinstalledPetal = PreinstalledPetal {
    name: "near-intents",
    repository: "https://github.com/bloom-directory/bloom-petal-near",
    commit: NEAR_INTENTS_INITIAL_RELEASE_COMMIT,
    release_tag: "v0.1.0",
    archive: "near-intents-v0.1.0.petal.tar.gz",
    expected_hash: Some("c78316d538e8364e837ed488fa74f04429d2477a617c36e7a6dc0c0fc68edee0"),
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

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct PetalReleaseManifest {
    schema: String,
    petal_name: String,
    source_repository: String,
    source_commit: String,
    release_tag: String,
    archive: String,
    archive_sha256: String,
    package_hash: String,
    tooling_repository: String,
    tooling_commit: String,
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

pub(crate) fn ensure_preinstalled_petals(_home: &HomeDir, daemon: &Daemon) -> Result<Vec<String>> {
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
        let installed = install_prebuilt_release_petal(daemon, entry)
        .with_context(|| {
            format!(
                "provision pre-installed Petal {} from {} release {} at commit {}; fix the cause and retry `bloom init`, or persistently opt out with `[petals] preinstalled = []`",
                entry.name, entry.repository, entry.release_tag, entry.commit
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

fn install_prebuilt_release_petal(
    daemon: &Daemon,
    entry: &PreinstalledPetal,
) -> Result<GitHubInstallOutput> {
    let repo = parse_github_install_url(entry.repository)?
        .ok_or_else(|| anyhow!("built-in Petal repository is not a GitHub source URL"))?;
    let release_base = format!(
        "https://github.com/{}/{}/releases/download/{}",
        repo.owner, repo.repo, entry.release_tag
    );

    let manifest_file =
        tempfile::NamedTempFile::new().context("create Petal release manifest download")?;
    curl_download(
        &format!("{release_base}/petal-release.json"),
        manifest_file.path(),
    )?;
    let manifest: PetalReleaseManifest = serde_json::from_reader(
        std::fs::File::open(manifest_file.path()).context("open Petal release manifest")?,
    )
    .context("parse Petal release manifest")?;
    validate_release_manifest(entry, &repo, &manifest)?;

    let url = format!("{release_base}/{}", entry.archive);
    let archive = tempfile::NamedTempFile::new().context("create pre-installed Petal download")?;
    curl_download(&url, archive.path())?;

    let checksums = tempfile::NamedTempFile::new().context("create release checksum download")?;
    curl_download(&format!("{release_base}/SHA256SUMS"), checksums.path())?;
    let archive_sha = verify_release_checksum(archive.path(), entry.archive, checksums.path())?;
    if !archive_sha.eq_ignore_ascii_case(&manifest.archive_sha256) {
        bail!(
            "Petal release manifest archive checksum does not match SHA256SUMS for {}",
            entry.archive
        );
    }
    install_prebuilt_petal_archive(daemon, entry, &manifest, archive.path())
}

fn curl_download(url: &str, output: &Path) -> Result<()> {
    match Command::new("curl")
        .args(["--fail", "--silent", "--show-error", "--location"])
        .arg(url)
        .arg("--output")
        .arg(output)
        .status()
    {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => bail!("download {url} with curl failed with status {status}"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!("curl is required to install pre-installed Petal releases")
        }
        Err(error) => Err(error).context("launch curl for pre-installed Petal archive"),
    }
}

fn verify_release_checksum(archive: &Path, name: &str, checksums: &Path) -> Result<String> {
    let body = std::fs::read_to_string(checksums)
        .with_context(|| format!("read Bloom release checksums from {}", checksums.display()))?;
    let expected = body
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let digest = fields.next()?;
            let file = fields.next()?.trim_start_matches('*');
            (file == name).then_some(digest)
        })
        .next()
        .ok_or_else(|| anyhow!("Bloom release checksums do not contain {name}"))?;
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Bloom release checksum for {name} is malformed");
    }

    let mut file = std::fs::File::open(archive)
        .with_context(|| format!("open downloaded Petal archive {}", archive.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).context("hash downloaded Petal archive")?;
    let actual = hex::encode(hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("Petal release checksum verification failed for {name}");
    }
    Ok(actual)
}

fn validate_release_manifest(
    entry: &PreinstalledPetal,
    repo: &GitHubRepo,
    manifest: &PetalReleaseManifest,
) -> Result<()> {
    if manifest.schema != "bloom.petal.release.v1" {
        bail!(
            "unsupported Petal release manifest schema {:?}",
            manifest.schema
        );
    }
    let expected_repository = format!("{}/{}", repo.owner, repo.repo);
    if manifest.petal_name != entry.name
        || manifest.source_repository != expected_repository
        || manifest.source_commit != entry.commit
        || manifest.release_tag != entry.release_tag
        || manifest.archive != entry.archive
    {
        bail!("Petal release manifest does not match the pinned catalog entry");
    }
    for (label, digest) in [
        ("archive_sha256", manifest.archive_sha256.as_str()),
        ("package_hash", manifest.package_hash.as_str()),
    ] {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("Petal release manifest {label} is not a 64-character hexadecimal digest");
        }
    }
    if manifest.tooling_commit.len() != 40
        || !manifest
            .tooling_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("Petal release manifest tooling_commit is not a full Git commit");
    }
    if manifest.tooling_repository != "bloom-directory/petal" {
        bail!("Petal release manifest names an untrusted tooling repository");
    }
    if let Some(expected_hash) = entry.expected_hash
        && manifest.package_hash != expected_hash
    {
        bail!("Petal release manifest package hash does not match the catalog");
    }
    Ok(())
}

fn install_prebuilt_petal_archive(
    daemon: &Daemon,
    entry: &PreinstalledPetal,
    release: &PetalReleaseManifest,
    archive: &Path,
) -> Result<GitHubInstallOutput> {
    let file = std::fs::File::open(archive)
        .with_context(|| format!("open pre-installed Petal archive {}", archive.display()))?;
    let package = PreparedPetalPackage::from_reader(GzDecoder::new(file))
        .context("validate pre-installed Petal release archive")?;
    if package.name != entry.name {
        bail!(
            "pre-installed Petal {} archive contains unexpected package {:?}",
            entry.name,
            package.name
        );
    }
    if package.hash != release.package_hash {
        bail!(
            "pre-installed Petal {} package hash {} does not match release manifest hash {}",
            entry.name,
            package.hash,
            release.package_hash
        );
    }
    if let Some(expected_hash) = entry.expected_hash
        && package.hash != expected_hash
    {
        bail!(
            "pre-installed Petal {} package hash {} does not match expected hash {}",
            entry.name,
            package.hash,
            expected_hash
        );
    }

    let mut consent = petal_consent_summary(&package).context("build Petal consent summary")?;
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

    let repo = parse_github_install_url(entry.repository)?
        .ok_or_else(|| anyhow!("built-in Petal repository is not a GitHub source URL"))?;
    let provenance = PetalSourceProvenance {
        source_kind: "github".to_string(),
        url: repo.canonical_url,
        owner: repo.owner,
        repo: repo.repo,
        requested_ref: entry.release_tag.to_string(),
        resolved_commit: entry.commit.to_string(),
        selected_tag: Some(entry.release_tag.to_string()),
        package_hash: package.hash.clone(),
    };
    let (result, meta, index) = daemon
        .petals
        .store()
        .install_prepared_petal_package_with_source(package, Some(provenance.clone()))
        .context("install pre-built Petal package")?;

    Ok(GitHubInstallOutput {
        result,
        meta,
        index,
        consent,
        provenance,
    })
}

fn preinstalled_petal(name: &str) -> Option<&'static PreinstalledPetal> {
    match name {
        "polymarket" => Some(&PREINSTALLED_POLYMARKET),
        "near-intents" => Some(&PREINSTALLED_NEAR_INTENTS),
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
        assert!(entry.archive.starts_with("polymarket-"));
        assert!(entry.archive.ends_with(".petal.tar.gz"));
        assert_eq!(
            entry.archive,
            format!("polymarket-{}.petal.tar.gz", entry.release_tag)
        );
        let near = preinstalled_petal("near-intents").unwrap();
        assert_eq!(near.release_tag, "v0.1.0");
        assert_eq!(near.commit.len(), 40);
        assert_eq!(near.archive, "near-intents-v0.1.0.petal.tar.gz");
        assert!(near.repository.ends_with("/bloom-petal-near"));
        assert!(preinstalled_petal("unknown").is_none());
    }

    #[test]
    fn existing_preinstalled_package_must_match_source_commit_and_hash() {
        let entry = preinstalled_petal("polymarket").unwrap();
        let hash = entry.expected_hash.unwrap().to_string();
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
    fn prebuilt_archive_installs_without_running_source_build() {
        let source = tempfile::tempdir().unwrap();
        write_source_repo(
            &source,
            "bloom-petal-test-prebuilt",
            true,
            &BuildScript::Success,
            "prebuilt",
        )
        .unwrap();
        run_source_build(source.path()).unwrap();
        let package = PreparedPetalPackage::from_dir(source.path()).unwrap();
        let archive = tempfile::NamedTempFile::new().unwrap();
        {
            let mut encoder = flate2::write::GzEncoder::new(
                archive.reopen().unwrap(),
                flate2::Compression::best(),
            );
            package.write_petal_tar(&mut encoder).unwrap();
            encoder.finish().unwrap();
        }

        let home = tempfile::tempdir().unwrap();
        let daemon = Daemon::from_home(HomeDir::at(home.path())).unwrap();
        let entry = PreinstalledPetal {
            name: "demo",
            repository: "https://github.com/bloom-directory/bloom-petal-test-prebuilt",
            commit: "1111111111111111111111111111111111111111",
            release_tag: "v0.1.0",
            archive: "unused.petal.tar.gz",
            expected_hash: None,
        };
        let release = PetalReleaseManifest {
            schema: "bloom.petal.release.v1".into(),
            petal_name: entry.name.into(),
            source_repository: "bloom-directory/bloom-petal-test-prebuilt".into(),
            source_commit: entry.commit.into(),
            release_tag: entry.release_tag.into(),
            archive: entry.archive.into(),
            archive_sha256: "2".repeat(64),
            package_hash: package.hash.clone(),
            tooling_repository: "bloom-directory/petal".into(),
            tooling_commit: "3".repeat(40),
        };
        let installed =
            install_prebuilt_petal_archive(&daemon, &entry, &release, archive.path()).unwrap();
        assert_eq!(installed.meta.hash, package.hash);
        assert_eq!(installed.provenance.source_kind, "github");
        assert_eq!(installed.provenance.resolved_commit, entry.commit);
        assert_eq!(
            daemon.petals.store().list_petal_owners().unwrap(),
            vec![("demo".to_string(), package.hash)]
        );
    }

    #[test]
    fn release_checksum_verification_is_name_bound_and_fail_closed() {
        let archive = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(archive.path(), b"petal archive").unwrap();
        let digest = hex::encode(Sha256::digest(b"petal archive"));
        let checksums = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            checksums.path(),
            format!(
                "{digest}  expected.petal.tar.gz\n{}  other\n",
                "0".repeat(64)
            ),
        )
        .unwrap();

        assert_eq!(
            verify_release_checksum(archive.path(), "expected.petal.tar.gz", checksums.path())
                .unwrap(),
            digest
        );
        let missing =
            verify_release_checksum(archive.path(), "missing.petal.tar.gz", checksums.path())
                .unwrap_err()
                .to_string();
        assert!(missing.contains("do not contain"), "{missing}");

        std::fs::write(archive.path(), b"tampered").unwrap();
        let mismatch =
            verify_release_checksum(archive.path(), "expected.petal.tar.gz", checksums.path())
                .unwrap_err()
                .to_string();
        assert!(mismatch.contains("verification failed"), "{mismatch}");
    }

    #[test]
    fn release_manifest_is_bound_to_catalog_source_and_artifact() {
        let entry = preinstalled_petal("polymarket").unwrap();
        let repo = parse_github_install_url(entry.repository).unwrap().unwrap();
        let mut manifest = PetalReleaseManifest {
            schema: "bloom.petal.release.v1".into(),
            petal_name: entry.name.into(),
            source_repository: format!("{}/{}", repo.owner, repo.repo),
            source_commit: entry.commit.into(),
            release_tag: entry.release_tag.into(),
            archive: entry.archive.into(),
            archive_sha256: "a".repeat(64),
            package_hash: entry.expected_hash.unwrap().into(),
            tooling_repository: "bloom-directory/petal".into(),
            tooling_commit: "c".repeat(40),
        };
        validate_release_manifest(entry, &repo, &manifest).unwrap();

        manifest.source_commit = "d".repeat(40);
        let mismatch = validate_release_manifest(entry, &repo, &manifest)
            .unwrap_err()
            .to_string();
        assert!(mismatch.contains("pinned catalog entry"), "{mismatch}");

        manifest.source_commit = entry.commit.into();
        manifest.package_hash = "b".repeat(64);
        let hash_mismatch = validate_release_manifest(entry, &repo, &manifest)
            .unwrap_err()
            .to_string();
        assert!(hash_mismatch.contains("package hash"), "{hash_mismatch}");

        manifest.package_hash = entry.expected_hash.unwrap().into();
        manifest.tooling_repository = "untrusted/petal".into();
        let untrusted = validate_release_manifest(entry, &repo, &manifest)
            .unwrap_err()
            .to_string();
        assert!(untrusted.contains("untrusted tooling"), "{untrusted}");
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
