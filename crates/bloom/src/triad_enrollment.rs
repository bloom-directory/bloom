//! Root-only generation of per-login triad identities and signing material
//! from public release templates.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use bloom_broker_api::{
    Base64UrlBytes, DecimalU64, Digest32, PROVENANCE_RECORD_SIGNATURE_DOMAIN,
    PetalLineageMembership, ProvenanceCatalog, ProvenanceFeeAsset, ProvenanceOperationClass,
    ProvenanceRecord, ProvenanceSubject, Token,
};
#[cfg(feature = "triad-dev-harness")]
use bloom_petals::package::build_petal_package_dir;
use ed25519_dalek::{Signer as _, SigningKey};
use rand::{RngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize as _;

const MAX_TEMPLATE_BYTES: u64 = 1024 * 1024;
const PUBLIC_TEMPLATE_FILES: [&str; 3] =
    ["edge-manifest.json.in", "broker.json.in", "signer.json.in"];

pub fn run(
    template_dir: PathBuf,
    output_dir: PathBuf,
    login_uid: u32,
    broker_uid: u32,
    signer_uid: u32,
    session_socket_gid: u32,
    release_digest: String,
) -> Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        bail!("macOS enrollment material generation requires root");
    }
    if std::env::consts::OS != "macos" {
        bail!("macOS enrollment material generation requires Darwin");
    }
    generate(&EnrollmentPlan {
        template_dir,
        output_dir,
        login_uid,
        broker_uid,
        signer_uid,
        session_socket_gid,
        release_digest,
    })
}

pub fn run_linux(
    template_dir: PathBuf,
    output_dir: PathBuf,
    login_uid: u32,
    broker_uid: u32,
    signer_uid: u32,
    session_socket_gid: u32,
    release_digest: String,
) -> Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        bail!("Linux enrollment material generation requires root");
    }
    if std::env::consts::OS != "linux" {
        bail!("Linux enrollment material generation requires Linux");
    }
    generate(&EnrollmentPlan {
        template_dir,
        output_dir,
        login_uid,
        broker_uid,
        signer_uid,
        session_socket_gid,
        release_digest,
    })
}

pub fn run_provenance_refresh(
    template: &Path,
    installer_identity: &Path,
    output: &Path,
) -> Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        bail!("triad provenance refresh requires root");
    }
    refresh_provenance_catalog_for_owner(template, installer_identity, output, 0)
}

fn refresh_provenance_catalog_for_owner(
    template: &Path,
    installer_identity: &Path,
    output: &Path,
    expected_owner: u32,
) -> Result<()> {
    require_private_file(installer_identity, expected_owner, "installer identity")?;
    if output.exists() {
        bail!("provenance refresh output already exists");
    }
    let mut identity_bytes = fs::read(installer_identity)?;
    let mut identity: OwnedInstallerIdentity =
        serde_json::from_slice(&identity_bytes).context("parse installer identity")?;
    identity_bytes.zeroize();
    if identity.schema != "bloom.installer-identity.1" {
        bail!("installer identity has an unsupported schema");
    }
    let mut seed = hex::decode(identity.private_key_seed_hex.as_bytes())
        .context("decode installer signing seed")?;
    identity.private_key_seed_hex.zeroize();
    let mut seed_array: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("installer signing seed is not 32 bytes"))?;
    let installer = GeneratedKey { seed: seed_array };
    seed_array.zeroize();
    seed.zeroize();
    if installer.public_hex() != identity.public_key_hex {
        bail!("installer identity public key does not match its signing seed");
    }
    sign_provenance_catalog(template, output, &identity.key_id, &installer)
}

#[cfg(feature = "triad-dev-harness")]
pub fn run_developer(template_dir: &Path, output_dir: &Path, release_digest: String) -> Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    validate_developer_caller(uid, std::env::consts::OS)?;
    let template_dir = fs::canonicalize(template_dir)
        .context("canonicalize developer enrollment template directory")?;
    let output_dir = fs::canonicalize(output_dir)
        .context("canonicalize developer enrollment output directory")?;
    let plan = EnrollmentPlan {
        template_dir,
        output_dir,
        login_uid: uid,
        broker_uid: uid,
        signer_uid: uid,
        session_socket_gid: gid,
        release_digest,
    };
    generate_for_owner(&plan, uid)?;
    let developer_root = plan
        .output_dir
        .parent()
        .context("developer config output has no parent root")?;
    render_developer_runtime_paths(&plan.output_dir, developer_root)
}

#[cfg(feature = "triad-dev-harness")]
pub fn run_developer_petal_provenance(config_dir: &Path, petal_dir: &Path) -> Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    validate_developer_caller(uid, std::env::consts::OS)?;
    let config_dir =
        fs::canonicalize(config_dir).context("canonicalize developer triad config directory")?;
    let petal_dir =
        fs::canonicalize(petal_dir).context("canonicalize developer Petal package directory")?;
    enroll_developer_petal_provenance(&config_dir, &petal_dir, uid)
}

#[cfg(any(test, feature = "triad-dev-harness"))]
fn validate_developer_caller(uid: u32, os: &str) -> Result<()> {
    if uid == 0 {
        bail!("developer enrollment material generation refuses root");
    }
    if !matches!(os, "linux" | "macos") {
        bail!("developer enrollment material generation requires Linux or macOS");
    }
    Ok(())
}

#[cfg(feature = "triad-dev-harness")]
const DEVELOPER_PETAL_LINEAGE_DOMAIN: &[u8] = b"bloom-developer-petal-lineage/v1";

#[cfg(feature = "triad-dev-harness")]
#[derive(Serialize)]
struct DeveloperPetalLineageStatement<'a> {
    schema: &'static str,
    lineage_id: &'a str,
    package_hash: &'a Digest32,
    release_sequence: DecimalU64,
    predecessor_package_hashes: &'a [Digest32],
    controller_key_id: &'a Token,
    publisher: &'a Token,
    active: bool,
}

#[cfg(feature = "triad-dev-harness")]
struct DeveloperPetalLineageInput<'a> {
    lineage_id: &'a str,
    package_hash: &'a Digest32,
    release_sequence: u64,
    predecessor_package_hashes: Vec<Digest32>,
    controller_key_id: &'a Token,
    publisher: &'a Token,
    active: bool,
}

fn base32_lower_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut output = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((accumulator >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits != 0 {
        output.push(ALPHABET[((accumulator << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

#[cfg(feature = "triad-dev-harness")]
fn developer_petal_lineage_id(publisher: &Token, package_name: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DEVELOPER_PETAL_LINEAGE_DOMAIN);
    hasher.update(&[0]);
    hasher.update(publisher.as_str().as_bytes());
    hasher.update(&[0]);
    hasher.update(package_name.as_bytes());
    format!("pln1_{}", base32_lower_no_pad(hasher.finalize().as_bytes()))
}

#[cfg(feature = "triad-dev-harness")]
fn sign_developer_petal_lineage(
    signing_key: &SigningKey,
    input: DeveloperPetalLineageInput<'_>,
) -> Result<PetalLineageMembership> {
    let mut message = DEVELOPER_PETAL_LINEAGE_DOMAIN.to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&DeveloperPetalLineageStatement {
        schema: "bloom.developer-petal-lineage.1",
        lineage_id: input.lineage_id,
        package_hash: input.package_hash,
        release_sequence: DecimalU64::new(input.release_sequence),
        predecessor_package_hashes: &input.predecessor_package_hashes,
        controller_key_id: input.controller_key_id,
        publisher: input.publisher,
        active: input.active,
    })?);
    let controller_signature = Base64UrlBytes::from_bytes(&signing_key.sign(&message).to_bytes());
    message.zeroize();
    Ok(PetalLineageMembership {
        lineage_id: input.lineage_id.to_owned(),
        release_sequence: DecimalU64::new(input.release_sequence),
        predecessor_package_hashes: input.predecessor_package_hashes,
        controller_key_id: input.controller_key_id.clone(),
        controller_signature,
        active: input.active,
    })
}

#[cfg(feature = "triad-dev-harness")]
fn load_developer_installer(config_dir: &Path) -> Result<(SigningKey, Token)> {
    let mut identity_bytes = fs::read(config_dir.join("installer-identity.json"))?;
    let mut identity: OwnedInstallerIdentity =
        serde_json::from_slice(&identity_bytes).context("parse developer installer identity")?;
    identity_bytes.zeroize();
    if identity.schema != "bloom.installer-identity.1" {
        bail!("developer installer identity has an unsupported schema");
    }
    let mut seed = hex::decode(identity.private_key_seed_hex.as_bytes())
        .context("decode developer installer signing seed")?;
    identity.private_key_seed_hex.zeroize();
    let mut seed_array: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("developer installer signing seed is not 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&seed_array);
    seed_array.zeroize();
    seed.zeroize();
    if hex::encode(signing_key.verifying_key().to_bytes()) != identity.public_key_hex {
        bail!("developer installer identity public key does not match its signing seed");
    }
    Ok((signing_key, Token::new(identity.key_id)?))
}

/// Re-sign a developer provenance catalog for the current binary, as packaged
/// upgrades do with `triad-refresh-provenance-catalog`: records come from the
/// current public template plus this binary's bundled Petal release pins.
/// Developer-owned records (fixtures, locally enrolled Petals) are kept.
/// Without this, a long-lived developer root keeps the release pins of the
/// binary that first created it, and newer bundled Petal releases can never
/// activate. Rewrites the catalog only when it changes.
#[cfg(feature = "triad-dev-harness")]
pub fn run_developer_provenance_refresh(template: &Path, config_dir: &Path) -> Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    validate_developer_caller(uid, std::env::consts::OS)?;
    let config_dir =
        fs::canonicalize(config_dir).context("canonicalize developer triad config directory")?;
    // Each line carries its own severity word: `note:` for a change that was
    // saved, `warning:` for a disagreement the refresh left alone. They are
    // returned rather than printed from inside the refresh so the tests can
    // assert on them without capturing stderr.
    for line in refresh_developer_provenance_catalog(template, &config_dir, uid)? {
        eprintln!("{line}");
    }
    Ok(())
}

#[cfg(feature = "triad-dev-harness")]
fn refresh_developer_provenance_catalog(
    template: &Path,
    config_dir: &Path,
    expected_owner: u32,
) -> Result<Vec<String>> {
    let catalog_path = config_dir.join("provenance-catalog.json");
    require_private_developer_file(
        &config_dir.join("installer-identity.json"),
        expected_owner,
        "installer identity",
    )?;
    require_private_developer_file(&catalog_path, expected_owner, "provenance catalog")?;
    let (signing_key, installer_key_id) = load_developer_installer(config_dir)?;
    let existing: ProvenanceCatalog =
        serde_json::from_slice(&fs::read(&catalog_path)?).context("parse provenance catalog")?;
    existing.validate_shape()?;
    let mut catalog: ProvenanceCatalog = serde_json::from_slice(&read_public_template(template)?)
        .context("parse unsigned provenance catalog")?;
    catalog.validate_shape()?;
    let release_publisher = Token::new("bloom-release-pins")?;
    let developer_records: Vec<ProvenanceRecord> = existing
        .records
        .iter()
        .filter(|record| {
            record.publisher != release_publisher
                && !catalog
                    .records
                    .iter()
                    .any(|template| template.subject == record.subject)
        })
        .cloned()
        .collect();
    // A developer record enrolled before a class was catalogued keeps the fee
    // asset it was written with, and this refresh re-signs it as valid, so the
    // stale value would outlive the upgrade: the Petal declares a fee the
    // catalogue says its class does not take, and Broker denies every one with
    // FEE_NOT_ALLOWED. Only `bloom-release-pins` records are rebuilt below, so
    // without this an upgraded developer triad stays silently broken until each
    // Petal is enrolled again by hand.
    //
    // Petal subjects only. The filter above already drops any record whose
    // subject the current template still lists, so the template's own System
    // records never reach this loop. What the guard protects is a System
    // subject the template has since dropped or renamed: it is carried here as
    // a developer record, and this table does not govern it, so it must keep
    // the fee asset it was signed with.
    //
    // Every Petal record IS governed, including the authority fixture that
    // `scripts/triad-dev-launch.sh` injects with `jq` — its hand-written
    // `fee_asset` literal is re-derived here like any other, so that literal
    // has to stay null unless its class joins the table.
    //
    // Healing a stale `None` is the point of the loop, and it proceeds with a
    // note on stderr. A value the record was already signed with is never
    // overwritten — not cleared, not replaced — because one of the record and
    // the table is stale and the refresh cannot tell which. Re-signing on a
    // guess denies the Petal's claims: `FEE_NOT_ALLOWED` where the value was
    // cleared, `FEE_ASSET_MISMATCH` where it was replaced. So the record is
    // left exactly as signed and the disagreement is reported instead.
    //
    // Reported, not refused. An earlier revision aborted the refresh on any
    // disagreement, which meant one stale record stopped every launch — the
    // launcher runs this before enrolment, so there was no way through it from
    // inside the launcher at all. Warning keeps what refusing was for, which
    // is that a record must never silently disagree with the table, without
    // holding a developer hostage to a record no claim in their session will
    // touch. The failure the warning prevents is a Broker denial at claim time
    // with nothing pointing back here.
    //
    // Lineage `active` is not consulted. A superseded record's `fee_asset`
    // still decides a claim that names its package hash, so there is no reason
    // to treat one differently, and nothing here overwrites a signed value in
    // either case. (No claim can name a superseded hash in practice:
    // `bloom-petals`' store flips a single owner pointer under the install
    // commit, and every dispatch path resolves through `resolve_petal_owner`.
    // That is why the distinction stopped being worth its machinery.)
    let mut developer_records = developer_records;
    let mut notes = Vec::new();
    let mut warnings = Vec::new();
    for record in &mut developer_records {
        if matches!(record.subject, ProvenanceSubject::Petal { .. }) {
            let (package_hash, route) = match &record.subject {
                ProvenanceSubject::Petal {
                    package_hash,
                    route,
                } => (package_hash.as_str().to_owned(), route.clone()),
                _ => (String::new(), String::new()),
            };
            for class in &mut record.operation_classes {
                let derived = catalogued_fee_asset(class.operation_class.as_str())?;
                if derived == class.fee_asset {
                    continue;
                }
                // Any disagreement, not only a clearing one. A record that
                // matched its Petal before the refresh would stop matching
                // after, and whether the symptom is FEE_NOT_ALLOWED (cleared)
                // or FEE_ASSET_MISMATCH (replaced with a different chain or
                // asset) the Petal is equally broken.
                if class.fee_asset.is_some() {
                    warnings.push(format!(
                        "warning: route {route} of package {package_hash} class {} is \
                         signed with {:?} but this build derives {:?}; left as signed",
                        class.operation_class.as_str(),
                        class.fee_asset,
                        derived,
                    ));
                    continue;
                }
                // The whole value, not just the asset: the guard above
                // compares chain and asset, so reporting the asset alone
                // described a chain-only change as "usdc to usdc".
                notes.push(format!(
                    "note: re-derived fee asset for {} from {:?} to {:?}",
                    class.operation_class.as_str(),
                    class.fee_asset,
                    derived,
                ));
                class.fee_asset = derived;
            }
        }
    }
    if !warnings.is_empty() {
        // The subcommand that fixes this is `hide = true`, so `--help` does
        // not list it. Printing the remedy without the command to run it is
        // what the earlier refusal did, and it left the operator stuck at the
        // one moment this message was their only output.
        warnings.push(format!(
            "warning: each record above keeps the fee asset it was signed with, and Broker \
             will judge its claims against that value, not against this build's \
             FEE_BEARING_OPERATION_CLASSES. Either this build's table is wrong for that \
             class or does not catalogue it, or the record is the stale side — a table row \
             corrected since this root was enrolled, or a Petal that has changed since. If \
             the record is right, make this build's table agree with what the Petal \
             declares. If the table is right, re-enrol that Petal to re-derive its records \
             from the table, which the launcher does not do for you. From the repository \
             root, once per Petal named above:\n\n  \
             cargo build -p bloom --no-default-features --features mount,triad-dev-harness\n  \
             target/debug/bloom init triad-enroll-developer-petal-provenance {} \
             <petal-package-dir>\n\nwhere <petal-package-dir> is that Petal's built \
             package directory, the same path the launcher takes from \
             BLOOM_TRIAD_DEV_HYPERLIQUID_PACKAGE. That re-derives only the package hash on \
             disk; recreating the developer root clears every record at once.",
            config_dir.display(),
        ));
    }
    notes.append(&mut warnings);
    catalog.records.extend(developer_records);
    append_release_petal_provenance(&mut catalog, &installer_key_id, &signing_key)?;
    for record in &mut catalog.records {
        record.installer_key_id = installer_key_id.clone();
        let mut message = PROVENANCE_RECORD_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&record.unsigned_canonical_bytes()?);
        record.installer_signature =
            Base64UrlBytes::from_bytes(&signing_key.sign(&message).to_bytes());
        message.zeroize();
    }
    catalog.records.sort_by_key(|record| {
        serde_jcs::to_vec(&record.subject).expect("provenance subject is serializable")
    });
    catalog.validate_shape()?;
    let mut current = existing;
    current.records.sort_by_key(|record| {
        serde_jcs::to_vec(&record.subject).expect("provenance subject is serializable")
    });
    if current == catalog {
        // Not `Vec::new()`. A disagreement writes nothing, so the catalog
        // comes out unchanged in exactly the case the warning exists for, and
        // returning nothing here would swallow it. A heal always changes the
        // catalog, so anything still in hand on this path is a warning.
        return Ok(notes);
    }
    rewrite_private_json(&catalog_path, &serde_json::to_value(catalog)?)?;
    Ok(notes)
}

#[cfg(feature = "triad-dev-harness")]
fn enroll_developer_petal_provenance(
    config_dir: &Path,
    petal_dir: &Path,
    expected_owner: u32,
) -> Result<()> {
    require_private_developer_file(
        &config_dir.join("installer-identity.json"),
        expected_owner,
        "installer identity",
    )?;
    require_private_developer_file(
        &config_dir.join("provenance-catalog.json"),
        expected_owner,
        "provenance catalog",
    )?;

    let (signing_key, installer_key_id) = load_developer_installer(config_dir)?;

    // The Petal's source build may have changed its generated route components
    // since a previous developer run left ignored package artifacts behind.
    // Refresh those artifacts before signing provenance so enrollment, install,
    // and subsequent cold-start runs all bind the same package bytes.
    let package = build_petal_package_dir(petal_dir)
        .map_err(|error| anyhow::anyhow!("build developer Petal package: {error}"))?;
    let publisher = Token::new("bloom-developer-local-package")?;
    let package_hash = Digest32::new(package.hash.clone())?;
    let lineage_id = developer_petal_lineage_id(&publisher, &package.name);
    let catalog_path = config_dir.join("provenance-catalog.json");
    let mut catalog: ProvenanceCatalog =
        serde_json::from_slice(&fs::read(&catalog_path)?).context("parse provenance catalog")?;
    catalog.validate_shape()?;

    let mut current_membership: Option<PetalLineageMembership> = None;
    let mut maximum_release_sequence = 0_u64;
    let mut active_predecessors = Vec::new();
    for record in &catalog.records {
        let (
            ProvenanceSubject::Petal {
                package_hash: existing,
                ..
            },
            Some(membership),
        ) = (&record.subject, &record.petal_lineage)
        else {
            continue;
        };
        if membership.lineage_id != lineage_id {
            continue;
        }
        if membership.controller_key_id != installer_key_id {
            bail!("developer Petal lineage is controlled by a different signing key");
        }
        maximum_release_sequence = maximum_release_sequence.max(membership.release_sequence.get());
        if existing == &package_hash {
            if current_membership
                .as_ref()
                .is_some_and(|current| current != membership)
            {
                bail!("developer Petal package has inconsistent lineage memberships");
            }
            current_membership = Some(membership.clone());
        } else if membership.active && !active_predecessors.contains(existing) {
            active_predecessors.push(existing.clone());
        }
    }
    active_predecessors.sort_by(|left, right| left.as_str().cmp(right.as_str()));

    let lineage = if let Some(current) = current_membership {
        if !current.active {
            bail!("developer enrollment refuses to reactivate an inactive Petal package");
        }
        if !active_predecessors.is_empty() {
            bail!("developer Petal lineage has a conflicting active package");
        }
        current
    } else {
        let release_sequence = maximum_release_sequence
            .checked_add(1)
            .context("developer Petal lineage release sequence overflow")?;
        for record in &mut catalog.records {
            let ProvenanceSubject::Petal {
                package_hash: existing,
                ..
            } = &record.subject
            else {
                continue;
            };
            let Some(membership) = &record.petal_lineage else {
                continue;
            };
            if membership.lineage_id == lineage_id && membership.active {
                record.petal_lineage = Some(sign_developer_petal_lineage(
                    &signing_key,
                    DeveloperPetalLineageInput {
                        lineage_id: &lineage_id,
                        package_hash: existing,
                        release_sequence: membership.release_sequence.get(),
                        predecessor_package_hashes: membership.predecessor_package_hashes.clone(),
                        controller_key_id: &installer_key_id,
                        publisher: &record.publisher,
                        active: false,
                    },
                )?);
            }
        }
        sign_developer_petal_lineage(
            &signing_key,
            DeveloperPetalLineageInput {
                lineage_id: &lineage_id,
                package_hash: &package_hash,
                release_sequence,
                predecessor_package_hashes: active_predecessors,
                controller_key_id: &installer_key_id,
                publisher: &publisher,
                active: true,
            },
        )?
    };

    let mut additions = Vec::new();
    for route in &package.route_index.routes {
        let operation_classes = developer_route_operation_classes(route)?;
        if operation_classes.is_empty() {
            continue;
        }
        additions.push(ProvenanceRecord {
            subject: ProvenanceSubject::Petal {
                package_hash: package_hash.clone(),
                route: route.route_id.clone(),
            },
            publisher: publisher.clone(),
            operation_classes,
            petal_lineage: Some(lineage.clone()),
            installer_key_id: installer_key_id.clone(),
            installer_signature: Base64UrlBytes::from_bytes(&[]),
        });
    }
    if additions.is_empty() {
        bail!(
            "developer Petal {} declares no route provenance operation classes",
            package.name
        );
    }

    catalog.records.retain(|record| {
        !matches!(
            &record.subject,
            ProvenanceSubject::Petal { package_hash: existing, .. } if existing == &package_hash
        )
    });
    catalog.records.extend(additions);
    for record in &mut catalog.records {
        let mut message = PROVENANCE_RECORD_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&record.unsigned_canonical_bytes()?);
        record.installer_signature =
            Base64UrlBytes::from_bytes(&signing_key.sign(&message).to_bytes());
        message.zeroize();
    }
    catalog.records.sort_by_key(|record| {
        serde_jcs::to_vec(&record.subject).expect("provenance subject is serializable")
    });
    catalog.validate_shape()?;
    rewrite_private_json(&catalog_path, &serde_json::to_value(catalog)?)?;
    Ok(())
}

#[cfg(feature = "triad-dev-harness")]
fn developer_route_operation_classes(
    route: &bloom_petals::package::RouteIndexRecord,
) -> Result<Vec<ProvenanceOperationClass>> {
    let mut classes = route
        .key_derive_operation_classes
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(intent) = &route.install_metadata.sign_intent {
        classes.insert(intent.clone());
    }
    classes
        .into_iter()
        .map(|operation_class| {
            Ok(ProvenanceOperationClass {
                fee_asset: catalogued_fee_asset(&operation_class)?,
                operation_class: Token::new(operation_class)?,
            })
        })
        .collect()
}

/// The one Hyperliquid operation class whose every claim declares a fee:
/// builder-bearing orders sign under it and nothing else does. No released
/// Petal emits it yet — that route split lives in bloom-petal-hyperliquid#19,
/// and the released Petal declares no builder class at all.
///
/// Owner-signed only, in practice. #19's Petal routes session-signed builder
/// orders here too, but the reusable key-scope approval is prepared with
/// `value_limits: Vec::new()` (`bloom-daemon`), and Broker refuses a claim
/// whose fee asset is absent from those limits with `VALUE_ASSET_NOT_ALLOWED`.
/// A builder fee is the first declared value ever to reach that approval —
/// plain session actions declare nothing — so the session path is denied at
/// use time until those limits are populated.
const HYPERLIQUID_BUILDER_ORDER_CLASS: &str = "hyperliquid.builder_order";

/// One row per operation class whose *every* claim declares an exact fee.
///
/// A row is only legitimate where the fee is derivable from what the owner
/// signs, and where Broker bounds the declared amount against it. Without the
/// first, nothing can check the figure; without the second, nothing does.
///
/// Adding a venue takes more than a row: it also needs the Petal-side route
/// split that makes the new class uniformly fee-bearing. A row for a class no
/// installed Petal emits stays inert. Releasing it additionally needs the
/// class on the Petal's `PetalAuthorityRoute` row in `github_source.rs` and a
/// pin bump, or `validate_release_authority` rejects the release for declaring
/// a class the pin does not list.
///
/// Cataloguing a fee asset makes a claim authorizable; it does not make the
/// operation reviewed, and registering the class in Broker's review tables is
/// not the remedy. Which venues qualify, why Polymarket's builder-code class
/// does not, and what Broker must bound first are recorded under
/// "Operation-class granularity and `fee_asset`" in
/// `docs/architecture/Sealed Approvals.md`.
const FEE_BEARING_OPERATION_CLASSES: &[CataloguedFeeAsset] = &[CataloguedFeeAsset {
    operation_class: HYPERLIQUID_BUILDER_ORDER_CLASS,
    chain: "hyperliquid",
    asset: "usdc",
}];

/// A fee-bearing operation class and the asset its declared fee must name.
struct CataloguedFeeAsset {
    operation_class: &'static str,
    chain: &'static str,
    asset: &'static str,
}

/// The fee asset a catalogued operation class is enrolled with, on both the
/// developer-harness and the release-pins path.
///
/// Broker treats `fee_asset: Some(_)` as "every claim in this class MUST
/// declare `DeclaredFee::Fee`" and denies `DeclaredFee::None` with
/// `FEE_REQUIRED`; a class without one denies any fee-declaring claim with
/// `FEE_NOT_ALLOWED` (see `account_declared_values` in bloom-broker's
/// `authority.rs`). A class therefore has to be uniformly fee-bearing or
/// uniformly fee-free, and a fee asset is only correct on a class whose
/// every claim carries an exact declared fee.
///
/// Venue classes that mix both are not that: Hyperliquid signs cancels,
/// leverage updates, and plain orders under `hyperliquid.agent_action`
/// (sessions) and `hyperliquid.order` (owner) with `{"kind":"none"}`, and
/// Polymarket signs plain CLOB orders under `polymarket.order.poly1271` the
/// same way, so those stay fee-free. A builder-bearing order is the one claim
/// that declares a fee, and it signs under its own class through a dedicated
/// route, which is what makes the fee asset safe to assert.
///
/// Every Petal class absent from `FEE_BEARING_OPERATION_CLASSES` stays `None`,
/// so enrollment cannot outrun what the Petals actually declare. This governs
/// Petal provenance only: the signed catalog also carries System records from
/// the shipped template, and one of those (`solana.native-transfer`) names a
/// fee asset of its own, since a native transfer always pays a network fee. See
/// "Operation-class granularity and `fee_asset`" in
/// `docs/architecture/Sealed Approvals.md`.
fn catalogued_fee_asset(operation_class: &str) -> Result<Option<ProvenanceFeeAsset>> {
    if let Some(catalogued) = FEE_BEARING_OPERATION_CLASSES
        .iter()
        .find(|candidate| candidate.operation_class == operation_class)
    {
        return Ok(Some(ProvenanceFeeAsset {
            chain: Token::new(catalogued.chain)?,
            asset: catalogued.asset.to_owned(),
        }));
    }
    Ok(None)
}

#[cfg(feature = "triad-dev-harness")]
fn require_private_developer_file(path: &Path, expected_owner: u32, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_TEMPLATE_BYTES
    {
        bail!("developer {label} is not an owner-only regular file");
    }
    Ok(())
}

#[cfg(any(test, feature = "triad-dev-harness"))]
fn render_developer_runtime_paths(config_dir: &Path, developer_root: &Path) -> Result<()> {
    let developer_root =
        fs::canonicalize(developer_root).context("canonicalize generated developer triad root")?;
    let state = developer_root.join("state");
    let runtime = developer_root.join("runtime");
    let mut broker: serde_json::Value =
        serde_json::from_slice(&fs::read(config_dir.join("broker.json"))?)?;
    broker["journal_path"] = state.join("broker/journal.db").display().to_string().into();
    broker["authority_path"] = state
        .join("broker/authority.db")
        .display()
        .to_string()
        .into();
    broker["ceremony_path"] = state
        .join("broker/ceremonies.db")
        .display()
        .to_string()
        .into();
    broker["signer_socket_path"] = runtime
        .join("signer/signer.sock")
        .display()
        .to_string()
        .into();
    broker["provenance_catalog_path"] = config_dir
        .join("provenance-catalog.json")
        .display()
        .to_string()
        .into();
    broker["network_containment"] = serde_json::Value::Null;

    let mut signer: serde_json::Value =
        serde_json::from_slice(&fs::read(config_dir.join("signer.json"))?)?;
    signer["database_path"] = state.join("signer/signer.db").display().to_string().into();
    signer["network_containment"] = serde_json::Value::Null;
    rewrite_private_json(&config_dir.join("broker.json"), &broker)?;
    rewrite_private_json(&config_dir.join("signer.json"), &signer)?;

    for name in ["broker.json", "signer.json"] {
        let bytes = fs::read(config_dir.join(name))?;
        if bytes.windows(2).any(|window| window == b"@B") {
            bail!("developer {name} retains an unresolved packaging placeholder");
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "triad-dev-harness"))]
fn rewrite_private_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    let temporary = path.with_extension("json.new");
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok::<_, anyhow::Error>(())
    })();
    bytes.zeroize();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub fn run_identity_rotation(current_identity: &Path, replacement_identity: &Path) -> Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        bail!("macOS identity rotation generation requires root");
    }
    if std::env::consts::OS != "macos" {
        bail!("macOS identity rotation generation requires Darwin");
    }
    generate_identity_rotation_for_owner(current_identity, replacement_identity, 0)
}

#[derive(Clone, Debug)]
struct EnrollmentPlan {
    template_dir: PathBuf,
    output_dir: PathBuf,
    login_uid: u32,
    broker_uid: u32,
    signer_uid: u32,
    session_socket_gid: u32,
    release_digest: String,
}

fn generate(plan: &EnrollmentPlan) -> Result<()> {
    generate_for_owner(plan, 0)
}

fn generate_for_owner(plan: &EnrollmentPlan, expected_owner: u32) -> Result<()> {
    validate_plan(plan, expected_owner)?;
    let machine = ApplicationIdentity::generate("bloom-machine", plan.login_uid);
    let broker = ApplicationIdentity::generate("bloom-broker", plan.login_uid);
    let signer = ApplicationIdentity::generate("bloom-signer", plan.login_uid);
    let revoke = ApplicationIdentity::generate("bloom-revoke-client", plan.login_uid);
    let session = ApplicationIdentity::generate("bloom-session", plan.login_uid);
    let broker_signing = GeneratedKey::new();
    let broker_audit = GeneratedKey::new();
    let broker_review = GeneratedKey::new();
    let signer_revocation = GeneratedKey::new();
    let signer_audit = GeneratedKey::new();
    let signer_ceremony = GeneratedKey::new();
    let installer = GeneratedKey::new();

    let replacements = SecretReplacements(BTreeMap::from([
        ("@LOGIN_UID@", plan.login_uid.to_string()),
        ("@BLOOM_BROKER_UID@", plan.broker_uid.to_string()),
        ("@BLOOM_SIGNER_UID@", plan.signer_uid.to_string()),
        ("@SESSION_SOCKET_GID@", plan.session_socket_gid.to_string()),
        ("@BUILD_DIGEST@", plan.release_digest.clone()),
        ("@MACHINE_BOOT_EPOCH@", machine.boot_epoch.clone()),
        (
            "@MACHINE_APPLICATION_KEY_ID@",
            machine.application_key_id.clone(),
        ),
        (
            "@MACHINE_APPLICATION_PUBLIC_KEY_HEX@",
            machine.key.public_hex(),
        ),
        ("@BROKER_BOOT_EPOCH@", broker.boot_epoch.clone()),
        (
            "@BROKER_APPLICATION_KEY_ID@",
            broker.application_key_id.clone(),
        ),
        (
            "@BROKER_APPLICATION_PUBLIC_KEY_HEX@",
            broker.key.public_hex(),
        ),
        ("@SIGNER_BOOT_EPOCH@", signer.boot_epoch.clone()),
        (
            "@SIGNER_APPLICATION_KEY_ID@",
            signer.application_key_id.clone(),
        ),
        (
            "@SIGNER_APPLICATION_PUBLIC_KEY_HEX@",
            signer.key.public_hex(),
        ),
        ("@REVOKE_BOOT_EPOCH@", revoke.boot_epoch.clone()),
        (
            "@REVOKE_APPLICATION_KEY_ID@",
            revoke.application_key_id.clone(),
        ),
        (
            "@REVOKE_APPLICATION_PUBLIC_KEY_HEX@",
            revoke.key.public_hex(),
        ),
        ("@SESSION_BOOT_EPOCH@", session.boot_epoch.clone()),
        (
            "@SESSION_APPLICATION_KEY_ID@",
            session.application_key_id.clone(),
        ),
        (
            "@SESSION_APPLICATION_PUBLIC_KEY_HEX@",
            session.key.public_hex(),
        ),
        ("@BROKER_SIGNING_SEED_HEX@", broker_signing.private_hex()),
        (
            "@BROKER_SIGNING_PUBLIC_KEY_HEX@",
            broker_signing.public_hex(),
        ),
        ("@BROKER_AUDIT_SEED_HEX@", broker_audit.private_hex()),
        ("@BROKER_REVIEW_SEED_HEX@", broker_review.private_hex()),
        ("@BROKER_REVIEW_PUBLIC_KEY_HEX@", broker_review.public_hex()),
        (
            "@SIGNER_REVOCATION_SEED_HEX@",
            signer_revocation.private_hex(),
        ),
        (
            "@SIGNER_REVOCATION_PUBLIC_KEY_HEX@",
            signer_revocation.public_hex(),
        ),
        ("@SIGNER_AUDIT_SEED_HEX@", signer_audit.private_hex()),
        ("@SIGNER_CEREMONY_SEED_HEX@", signer_ceremony.private_hex()),
        (
            "@SIGNER_CEREMONY_PUBLIC_KEY_HEX@",
            signer_ceremony.public_hex(),
        ),
        ("@INSTALLER_PUBLIC_KEY_HEX@", installer.public_hex()),
    ]));

    for name in PUBLIC_TEMPLATE_FILES {
        let mut rendered = render_public_template(&plan.template_dir.join(name), &replacements.0)?;
        let result = write_new_private(
            &plan.output_dir.join(name.trim_end_matches(".in")),
            rendered.as_bytes(),
        );
        rendered.zeroize();
        result?;
    }
    write_identity(&plan.output_dir.join("machine-identity.json"), &machine)?;
    write_identity(&plan.output_dir.join("broker-identity.json"), &broker)?;
    write_identity(&plan.output_dir.join("signer-identity.json"), &signer)?;
    write_identity(&plan.output_dir.join("revoke-identity.json"), &revoke)?;
    write_identity(&plan.output_dir.join("session-identity.json"), &session)?;

    let installer_key_id = format!("bloom-installer-{}", plan.login_uid);
    write_installer_identity(
        &plan.output_dir.join("installer-identity.json"),
        &installer_key_id,
        &installer,
    )?;
    sign_provenance_catalog(
        &plan.template_dir.join("provenance-catalog.unsigned.json"),
        &plan.output_dir.join("provenance-catalog.json"),
        &installer_key_id,
        &installer,
    )?;

    Ok(())
}

fn generate_identity_rotation_for_owner(
    current_manifest_path: &Path,
    output_dir: &Path,
    expected_owner: u32,
) -> Result<()> {
    require_public_template(current_manifest_path, expected_owner)?;
    require_empty_private_output(output_dir, expected_owner)?;
    let mut manifest_bytes = read_public_template(current_manifest_path)?;
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).context("parse installed edge manifest")?;
    manifest_bytes.zeroize();
    if manifest.get("schema").and_then(|value| value.as_str()) != Some("bloom.edge-manifest.1") {
        bail!("installed edge manifest has the wrong schema");
    }
    let login_uid = manifest_uid(&manifest, "machine")?;
    if manifest_uid(&manifest, "revoke_client")? != login_uid
        || manifest_uid(&manifest, "session")? != login_uid
    {
        bail!("installed edge manifest has inconsistent login identities");
    }
    let broker_uid = manifest_uid(&manifest, "broker")?;
    let signer_uid = manifest_uid(&manifest, "signer")?;
    if broker_uid == login_uid || signer_uid == login_uid || signer_uid == broker_uid {
        bail!("installed edge manifest does not use distinct service UIDs");
    }
    let _session_gid = manifest
        .get("session_socket_gid")
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value != 0)
        .context("installed edge manifest session socket GID is invalid")?;
    let identities = [
        (
            "machine",
            ApplicationIdentity::generate("bloom-machine", login_uid),
        ),
        (
            "broker",
            ApplicationIdentity::generate("bloom-broker", login_uid),
        ),
        (
            "signer",
            ApplicationIdentity::generate("bloom-signer", login_uid),
        ),
        (
            "revoke_client",
            ApplicationIdentity::generate("bloom-revoke-client", login_uid),
        ),
        (
            "session",
            ApplicationIdentity::generate("bloom-session", login_uid),
        ),
    ];
    for (edge_name, identity) in &identities {
        replace_manifest_identity(&mut manifest, edge_name, identity)?;
    }
    let mut edge_bytes = serde_json::to_vec_pretty(&manifest)?;
    edge_bytes.push(b'\n');
    let result = write_new_private(&output_dir.join("edge-manifest.json"), &edge_bytes);
    edge_bytes.zeroize();
    result?;
    for (edge_name, identity) in &identities {
        let file_name = match *edge_name {
            "revoke_client" => "revoke-identity.json",
            other => {
                let mut name = other.to_owned();
                name.push_str("-identity.json");
                write_identity(&output_dir.join(name), identity)?;
                continue;
            }
        };
        write_identity(&output_dir.join(file_name), identity)?;
    }
    Ok(())
}

fn manifest_uid(manifest: &serde_json::Value, edge_name: &str) -> Result<u32> {
    let edge = manifest
        .get(edge_name)
        .and_then(|value| value.as_object())
        .with_context(|| format!("installed edge manifest omits {edge_name}"))?;
    let uid = edge
        .get("effective_uid")
        .and_then(|value| value.as_u64())
        .with_context(|| format!("installed edge manifest {edge_name} UID is invalid"))?;
    u32::try_from(uid)
        .ok()
        .filter(|uid| *uid != 0)
        .with_context(|| format!("installed edge manifest {edge_name} UID is invalid"))
}

fn replace_manifest_identity(
    manifest: &mut serde_json::Value,
    edge_name: &str,
    identity: &ApplicationIdentity,
) -> Result<()> {
    let edge = manifest
        .get_mut(edge_name)
        .and_then(|value| value.as_object_mut())
        .with_context(|| format!("installed edge manifest omits {edge_name}"))?;
    if edge.get("service_id").and_then(|value| value.as_str()) != Some(&identity.service_id) {
        bail!("installed edge manifest {edge_name} service identity is invalid");
    }
    edge.insert(
        "boot_epoch".to_owned(),
        serde_json::Value::String(identity.boot_epoch.clone()),
    );
    edge.insert(
        "application_key_id".to_owned(),
        serde_json::Value::String(identity.application_key_id.clone()),
    );
    edge.insert(
        "application_public_key_hex".to_owned(),
        serde_json::Value::String(identity.key.public_hex()),
    );
    Ok(())
}

fn validate_plan(plan: &EnrollmentPlan, expected_owner: u32) -> Result<()> {
    if plan.login_uid == 0
        || plan.broker_uid == 0
        || plan.signer_uid == 0
        || plan.session_socket_gid == 0
        || plan.release_digest.len() != 64
        || !plan
            .release_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("triad enrollment generation plan has invalid IDs or release digest");
    }
    require_empty_private_output(&plan.output_dir, expected_owner)?;
    for name in PUBLIC_TEMPLATE_FILES
        .into_iter()
        .chain(["provenance-catalog.unsigned.json"])
    {
        require_public_template(&plan.template_dir.join(name), expected_owner)?;
    }
    Ok(())
}

fn require_empty_private_output(output_dir: &Path, expected_owner: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(output_dir).with_context(|| {
        format!(
            "inspect enrollment output directory {}",
            output_dir.display()
        )
    })?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o7777 != 0o700
        || fs::read_dir(output_dir)?.next().is_some()
    {
        bail!("enrollment output must be an empty root-owned mode-0700 directory");
    }
    Ok(())
}

fn require_public_template(path: &Path, expected_owner: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect public template {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
        || metadata.len() > MAX_TEMPLATE_BYTES
    {
        bail!("enrollment template is not an immutable root-owned regular file");
    }
    Ok(())
}

fn render_public_template(path: &Path, replacements: &BTreeMap<&str, String>) -> Result<String> {
    let mut rendered =
        String::from_utf8(read_public_template(path)?).context("public template is not UTF-8")?;
    for (placeholder, value) in replacements {
        rendered = rendered.replace(placeholder, value);
    }
    for forbidden in [
        "_SEED_HEX@",
        "_BOOT_EPOCH@",
        "_APPLICATION_KEY_ID@",
        "_APPLICATION_PUBLIC_KEY_HEX@",
        "@INSTALLER_PUBLIC_KEY_HEX@",
        "@BUILD_DIGEST@",
    ] {
        if rendered.contains(forbidden) {
            rendered.zeroize();
            bail!("public template contains an unresolved security placeholder");
        }
    }
    if let Err(error) = serde_json::from_str::<serde_json::Value>(&rendered) {
        rendered.zeroize();
        return Err(error).context("rendered enrollment template is not JSON");
    }
    Ok(rendered)
}

fn read_public_template(path: &Path) -> Result<Vec<u8>> {
    let bytes =
        fs::read(path).with_context(|| format!("read public template {}", path.display()))?;
    if bytes.len() as u64 > MAX_TEMPLATE_BYTES {
        bail!("public enrollment template exceeds 1 MiB");
    }
    Ok(bytes)
}

fn write_identity(path: &Path, identity: &ApplicationIdentity) -> Result<()> {
    let mut private_key_seed_hex = identity.key.private_hex();
    let mut bytes = serde_json::to_vec_pretty(&IdentityDocument {
        service_id: &identity.service_id,
        boot_epoch: &identity.boot_epoch,
        application_key_id: &identity.application_key_id,
        private_key_seed_hex: &private_key_seed_hex,
    })?;
    bytes.push(b'\n');
    let result = write_new_private(path, &bytes);
    bytes.zeroize();
    private_key_seed_hex.zeroize();
    result
}

fn write_installer_identity(path: &Path, key_id: &str, key: &GeneratedKey) -> Result<()> {
    let mut private_key_seed_hex = key.private_hex();
    let mut public_key_hex = key.public_hex();
    let mut bytes = serde_json::to_vec_pretty(&InstallerIdentity {
        schema: "bloom.installer-identity.1",
        key_id,
        private_key_seed_hex: &private_key_seed_hex,
        public_key_hex: &public_key_hex,
    })?;
    bytes.push(b'\n');
    let result = write_new_private(path, &bytes);
    bytes.zeroize();
    private_key_seed_hex.zeroize();
    public_key_hex.zeroize();
    result
}

fn sign_provenance_catalog(
    source: &Path,
    destination: &Path,
    installer_key_id: &str,
    installer: &GeneratedKey,
) -> Result<()> {
    let mut source_bytes = read_public_template(source)?;
    let mut catalog: ProvenanceCatalog =
        serde_json::from_slice(&source_bytes).context("parse unsigned provenance catalog")?;
    source_bytes.zeroize();
    catalog.validate_shape()?;
    let installer_key_id = Token::new(installer_key_id)?;
    append_release_petal_provenance(&mut catalog, &installer_key_id, &installer.signing_key())?;
    for record in &mut catalog.records {
        record.installer_key_id = installer_key_id.clone();
        record.installer_signature = Base64UrlBytes::from_bytes(&[]);
        let mut message = PROVENANCE_RECORD_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&serde_jcs::to_vec(&record)?);
        record.installer_signature =
            Base64UrlBytes::from_bytes(&installer.signing_key().sign(&message).to_bytes());
        message.zeroize();
    }
    let mut catalog_bytes = serde_json::to_vec_pretty(&catalog)?;
    catalog_bytes.push(b'\n');
    let result = write_new_private(destination, &catalog_bytes);
    catalog_bytes.zeroize();
    result
}

fn append_release_petal_provenance(
    catalog: &mut ProvenanceCatalog,
    installer_key_id: &Token,
    signing_key: &SigningKey,
) -> Result<()> {
    append_release_petal_provenance_for_entries(
        catalog,
        installer_key_id,
        signing_key,
        &crate::github_source::release_lineage_petals(),
    )
}

/// Appends the lineage record, and one provenance record per authority
/// route, of every pinned release Petal in `entries`, cataloguing each
/// route's operation classes with the fee asset `catalogued_fee_asset`
/// assigns them.
fn append_release_petal_provenance_for_entries(
    catalog: &mut ProvenanceCatalog,
    installer_key_id: &Token,
    signing_key: &SigningKey,
    entries: &[&crate::github_source::PreinstalledPetal],
) -> Result<()> {
    let publisher = Token::new("bloom-release-pins")?;
    let mut package_hashes = std::collections::BTreeSet::new();
    let mut lineage_ids = std::collections::BTreeSet::new();
    for entry in entries {
        let package_hash = Digest32::new(
            entry
                .expected_hash
                .context("release Petal has no package hash")?,
        )?;
        let lineage_id = entry
            .lineage_id
            .map(str::to_owned)
            .unwrap_or_else(|| release_petal_lineage_id(&publisher, entry.name));
        bloom_broker_api::validate_lineage_id(&lineage_id)?;
        if entry.release_sequence == 0
            || !package_hashes.insert(package_hash.as_str().to_owned())
            || !lineage_ids.insert(lineage_id.clone())
        {
            bail!("release Petal contains an invalid or duplicate lineage");
        }
        let predecessors = entry
            .predecessor_package_hashes
            .iter()
            .map(|hash| Digest32::new(*hash))
            .collect::<Result<Vec<_>, _>>()?;
        let history = crate::github_source::release_lineage_predecessors(entry.name);
        let baseline = history
            .first()
            .context("bundled Petal has no baseline release hash")?;
        if package_hash.as_str() != baseline.hash
            && (entry.release_sequence <= 1
                || !predecessors
                    .iter()
                    .any(|hash| hash.as_str() == baseline.hash))
        {
            bail!(
                "successor {} must advance its release sequence and list its baseline hash",
                entry.name
            );
        }
        // The Machine refuses to replace an installed release that the
        // successor lists but the catalog lacks, so record every one.
        for hash in &predecessors {
            let old = history
                .iter()
                .find(|old| old.hash == hash.as_str())
                .with_context(|| {
                    format!("{} predecessor {hash} has no recorded release", entry.name)
                })?;
            let old_predecessors = old
                .predecessor_package_hashes
                .iter()
                .map(|hash| Digest32::new(*hash))
                .collect::<Result<Vec<_>, _>>()?;
            append_release_lineage_record(
                catalog,
                signing_key,
                installer_key_id,
                &publisher,
                &lineage_id,
                hash,
                old.release_sequence,
                &old_predecessors,
                false,
                old.authority_routes,
            )?;
        }
        append_release_lineage_record(
            catalog,
            signing_key,
            installer_key_id,
            &publisher,
            &lineage_id,
            &package_hash,
            entry.release_sequence,
            &predecessors,
            true,
            entry.authority_routes,
        )?;
    }
    catalog.validate_shape()?;
    Ok(())
}

fn release_petal_lineage_id(publisher: &Token, package_name: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom-release-petal-lineage-id/v1");
    hasher.update(&[0]);
    hasher.update(publisher.as_str().as_bytes());
    hasher.update(&[0]);
    hasher.update(package_name.as_bytes());
    format!("pln1_{}", base32_lower_no_pad(hasher.finalize().as_bytes()))
}

#[allow(clippy::too_many_arguments)]
fn append_release_lineage_record(
    catalog: &mut ProvenanceCatalog,
    signing_key: &SigningKey,
    installer_key_id: &Token,
    publisher: &Token,
    lineage_id: &str,
    package_hash: &Digest32,
    release_sequence: u64,
    predecessors: &[Digest32],
    active: bool,
    authority_routes: &[crate::github_source::PetalAuthorityRoute],
) -> Result<()> {
    #[derive(Serialize)]
    struct LineageStatement<'a> {
        schema: &'static str,
        lineage_id: &'a str,
        package_hash: &'a Digest32,
        release_sequence: DecimalU64,
        predecessor_package_hashes: &'a [Digest32],
        controller_key_id: &'a Token,
        publisher: &'a Token,
        active: bool,
    }
    let mut message = b"bloom-release-petal-lineage/v1".to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&LineageStatement {
        schema: "bloom.release-petal-lineage.1",
        lineage_id,
        package_hash,
        release_sequence: DecimalU64::new(release_sequence),
        predecessor_package_hashes: predecessors,
        controller_key_id: installer_key_id,
        publisher,
        active,
    })?);
    let lineage = PetalLineageMembership {
        lineage_id: lineage_id.to_owned(),
        release_sequence: DecimalU64::new(release_sequence),
        predecessor_package_hashes: predecessors.to_vec(),
        controller_key_id: installer_key_id.clone(),
        controller_signature: Base64UrlBytes::from_bytes(&signing_key.sign(&message).to_bytes()),
        active,
    };
    message.zeroize();
    // No authority class is assigned to these metadata-only records. The
    // Broker accepts their shape for lineage but rejects them for approvals.
    if authority_routes.is_empty() {
        catalog.records.push(ProvenanceRecord {
            subject: ProvenanceSubject::Petal {
                package_hash: package_hash.clone(),
                route: "__lineage__".into(),
            },
            publisher: publisher.clone(),
            petal_lineage: Some(lineage),
            operation_classes: vec![],
            installer_key_id: installer_key_id.clone(),
            installer_signature: Base64UrlBytes::from_bytes(&[]),
        });
    } else {
        for route in authority_routes {
            let operation_classes = route
                .operation_classes
                .iter()
                .map(|class| {
                    Ok(ProvenanceOperationClass {
                        operation_class: Token::new(*class)?,
                        fee_asset: catalogued_fee_asset(class)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            catalog.records.push(ProvenanceRecord {
                subject: ProvenanceSubject::Petal {
                    package_hash: package_hash.clone(),
                    route: route.route_id.to_owned(),
                },
                publisher: publisher.clone(),
                petal_lineage: Some(lineage.clone()),
                operation_classes,
                installer_key_id: installer_key_id.clone(),
                installer_signature: Base64UrlBytes::from_bytes(&[]),
            });
        }
    }
    Ok(())
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", path.display()))
}

fn require_private_file(path: &Path, expected_owner: u32, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_TEMPLATE_BYTES
    {
        bail!("{label} is not an owner-only regular file");
    }
    Ok(())
}

struct ApplicationIdentity {
    service_id: String,
    boot_epoch: String,
    application_key_id: String,
    key: GeneratedKey,
}

impl ApplicationIdentity {
    fn generate(service_id: &str, login_uid: u32) -> Self {
        let mut epoch = [0_u8; 16];
        OsRng.fill_bytes(&mut epoch);
        let boot_epoch = hex::encode(epoch);
        Self {
            service_id: service_id.to_owned(),
            application_key_id: format!("{service_id}-app-{login_uid}-{}", &boot_epoch[..16]),
            boot_epoch,
            key: GeneratedKey::new(),
        }
    }
}

struct GeneratedKey {
    seed: [u8; 32],
}

struct SecretReplacements(BTreeMap<&'static str, String>);

impl Drop for SecretReplacements {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

impl GeneratedKey {
    fn new() -> Self {
        let mut seed = [0_u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self { seed }
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    fn private_hex(&self) -> String {
        hex::encode(self.seed)
    }

    fn public_hex(&self) -> String {
        hex::encode(self.signing_key().verifying_key().to_bytes())
    }
}

impl Drop for GeneratedKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

#[derive(Serialize)]
struct IdentityDocument<'a> {
    service_id: &'a str,
    boot_epoch: &'a str,
    application_key_id: &'a str,
    private_key_seed_hex: &'a str,
}

#[derive(Serialize)]
struct InstallerIdentity<'a> {
    schema: &'static str,
    key_id: &'a str,
    private_key_seed_hex: &'a str,
    public_key_hex: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedInstallerIdentity {
    schema: String,
    key_id: String,
    private_key_seed_hex: String,
    public_key_hex: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "triad-dev-harness")]
    use bloom_petals::package::PreparedPetalPackage;
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
    use std::os::unix::fs::PermissionsExt as _;

    /// Building the fixture Petal rewrites its package artifacts in place, so
    /// tests that build it must not run concurrently.
    #[cfg(feature = "triad-dev-harness")]
    static FIXTURE_PETAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Every refresh test wants the same root: a generated developer
    /// enrollment with the authority-fixture Petal enrolled into it, so the
    /// catalog holds a developer-published record to plant on. Six copies of
    /// this were the bulk of what a review called ~900 lines of refresh tests.
    ///
    /// The mutex guard and the tempdir have to outlive the test body — dropping
    /// either mid-test deletes the root or lets a concurrent test rebuild the
    /// fixture Petal underneath it — so they are held here rather than
    /// returned alongside.
    #[cfg(feature = "triad-dev-harness")]
    struct RefreshRoot {
        _guard: std::sync::MutexGuard<'static, ()>,
        _directory: tempfile::TempDir,
        config: PathBuf,
        catalog_path: PathBuf,
        owner: u32,
    }

    #[cfg(feature = "triad-dev-harness")]
    impl RefreshRoot {
        fn enrolled() -> Self {
            let guard = FIXTURE_PETAL
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let directory = tempfile::tempdir().unwrap();
            let config = directory.path().join("config");
            fs::create_dir(&config).unwrap();
            fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).unwrap();
            let owner = rustix::process::geteuid().as_raw();
            let plan = EnrollmentPlan {
                template_dir: template_dir(),
                output_dir: config.clone(),
                login_uid: 1_001,
                broker_uid: 1_002,
                signer_uid: 1_003,
                session_socket_gid: 1_004,
                release_digest: "44".repeat(32),
            };
            generate_for_owner(&plan, owner).unwrap();
            let petal_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .unwrap()
                .join("tests/fixtures/triad-authority-petal");
            enroll_developer_petal_provenance(&config, &petal_dir, owner).unwrap();
            let catalog_path = config.join("provenance-catalog.json");
            Self {
                _guard: guard,
                _directory: directory,
                config,
                catalog_path,
                owner,
            }
        }

        fn catalog(&self) -> ProvenanceCatalog {
            serde_json::from_slice(&fs::read(&self.catalog_path).unwrap()).unwrap()
        }

        fn write(&self, catalog: &ProvenanceCatalog) {
            rewrite_private_json(&self.catalog_path, &serde_json::to_value(catalog).unwrap())
                .unwrap();
        }

        fn refresh(&self) -> Result<Vec<String>> {
            refresh_developer_provenance_catalog(
                &template_dir().join("provenance-catalog.unsigned.json"),
                &self.config,
                self.owner,
            )
        }
    }

    fn template_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join("packaging/triad/macos/config")
    }

    #[test]
    fn developer_enrollment_platform_policy_accepts_non_root_linux_and_macos_only() {
        validate_developer_caller(1000, "linux").unwrap();
        validate_developer_caller(501, "macos").unwrap();

        assert!(
            validate_developer_caller(0, "linux")
                .unwrap_err()
                .to_string()
                .contains("refuses root")
        );
        assert!(
            validate_developer_caller(1000, "windows")
                .unwrap_err()
                .to_string()
                .contains("Linux or macOS")
        );
    }

    #[cfg(feature = "triad-dev-harness")]
    #[test]
    fn developer_route_provenance_unions_only_immediate_and_explicit_classes() {
        let route = bloom_petals::package::RouteIndexRecord {
            route_id: "r000001".into(),
            pattern: "session.json".into(),
            source_path: "petal/fixture/session.json.wasm".into(),
            artifact_path: "artifacts/routes/r000001.wasm".into(),
            artifact_hash: "00".repeat(32),
            abi: bloom_petals::package::RouteAbi::ComponentBloomRoute010,
            kind: bloom_petals::package::RouteEntryKind::File,
            ops: vec![bloom_petals::package::RouteOp::Read],
            params: Vec::new(),
            specificity: [1, 1, 1],
            install_metadata: bloom_petals::package::InstallRouteMetadata {
                mode: 0o444,
                cache_ttl_ms: None,
                side_effecting_read: false,
                write_async: false,
                executable: false,
                required_caps: vec!["bloom:key.derive".into(), "bloom:sign".into()],
                sign_intent: Some("fixture.immediate".into()),
            },
            key_derive_operation_classes: vec![
                "fixture.delegated".into(),
                "fixture.immediate".into(),
            ],
            key_derive_allowed_routes: vec!["r000001".into()],
            key_derive_scope_declared: true,
            key_derive_allowed_crypto_suites: vec!["secp256k1-keccak256-recoverable".into()],
            key_derive_maximum_lifetime_ms: Some(60_000),
        };

        let records = developer_route_operation_classes(&route).unwrap();
        let classes = records
            .iter()
            .map(|class| class.operation_class.to_string())
            .collect::<Vec<_>>();
        assert_eq!(classes, ["fixture.delegated", "fixture.immediate"]);
        assert!(!classes.contains(&"fixture.package_wide".to_string()));
        assert!(records.iter().all(|class| class.fee_asset.is_none()));
    }

    #[test]
    fn only_builder_order_petal_classes_are_catalogued_with_a_fee_asset() {
        // Every Hyperliquid class Broker registers for message review, plus
        // the session class and Polymarket's. Listing them individually is
        // not enough on its own — a row added for a class absent from this
        // list would pass — so the table's own length is pinned below.
        for class in [
            "hyperliquid.agent_action",
            "hyperliquid.order",
            "hyperliquid.approve_builder_fee",
            "hyperliquid.approve_agent",
            "hyperliquid.cancel",
            "hyperliquid.cancel_by_cloid",
            "hyperliquid.schedule_cancel",
            "hyperliquid.update_leverage",
            "hyperliquid.usd_send",
            "hyperliquid.usd_class_transfer",
            // Absent on purpose: a withdrawal's claim declares
            // `{"kind":"none"}` and the venue's flat USDC fee is deliberately
            // left outside it, travelling in the operation record and the
            // signing advisory instead. Cataloguing a fee asset here would
            // make Broker answer FEE_REQUIRED for every withdrawal.
            "hyperliquid.withdraw",
            "polymarket.onboard",
            "polymarket.order.poly1271",
            "polymarket.relayer_batch",
            "polymarket.clob_auth.v1",
            // Absent on purpose: nothing bounds a Polymarket builder fee, so
            // Broker must keep refusing a claim that declares one.
            "polymarket.builder_code_order.poly1271",
        ] {
            assert!(
                catalogued_fee_asset(class).unwrap().is_none(),
                "{class} must stay fee-free"
            );
        }

        // Hyperliquid's builder-order class is the only catalogued row, now
        // that Polymarket's is deliberately fee-free. Pinned by count as well
        // as by name, so that cataloguing any further class has to come here
        // and be argued for rather than ride in on a table edit alone.
        assert_eq!(
            FEE_BEARING_OPERATION_CLASSES.len(),
            1,
            "a new fee-bearing row needs its own case in this test"
        );
        let class = "hyperliquid.builder_order";
        let fee = catalogued_fee_asset(class)
            .unwrap()
            .unwrap_or_else(|| panic!("{class} declares a fee on every claim"));
        assert_eq!(fee.chain.as_str(), "hyperliquid", "{class} fee chain");
        assert_eq!(fee.asset, "usdc", "{class} fee asset");
    }

    /// A fee-bearing class is only safe when a dedicated route makes every one
    /// of its claims declare a fee, so each row must name a class distinct
    /// from the fee-free class it was split out of, and must resolve.
    #[test]
    fn every_catalogued_fee_bearing_row_is_distinct_and_resolvable() {
        let classes = FEE_BEARING_OPERATION_CLASSES
            .iter()
            .map(|entry| entry.operation_class)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            classes.len(),
            FEE_BEARING_OPERATION_CLASSES.len(),
            "a class may be catalogued with only one fee asset"
        );
        for entry in FEE_BEARING_OPERATION_CLASSES {
            Token::new(entry.operation_class)
                .unwrap_or_else(|_| panic!("{} is not a valid class token", entry.operation_class));
            Token::new(entry.chain)
                .unwrap_or_else(|_| panic!("{} is not a valid chain token", entry.chain));
            assert!(!entry.asset.is_empty(), "{} needs an asset", entry.chain);
        }
    }

    fn release_catalog_for(
        entries: &[&crate::github_source::PreinstalledPetal],
    ) -> ProvenanceCatalog {
        let mut catalog = ProvenanceCatalog {
            schema: bloom_broker_api::PROVENANCE_CATALOG_SCHEMA.to_owned(),
            records: Vec::new(),
        };
        append_release_petal_provenance_for_entries(
            &mut catalog,
            &Token::new("installer").unwrap(),
            &SigningKey::from_bytes(&[7; 32]),
            entries,
        )
        .unwrap();
        catalog
    }

    /// The release path catalogues a pinned builder-order route fee-bearing.
    ///
    /// The real Hyperliquid pin cannot carry `hyperliquid.builder_order`
    /// until bloom-petal-hyperliquid#19 is released, so this proves the code
    /// path with a synthetic pin: the moment the pin lists the route, its
    /// class is enrolled with the usdc fee asset, and the shared class it is
    /// pinned alongside stays fee-free.
    #[test]
    fn release_enrollment_catalogues_a_pinned_builder_order_route_fee_bearing() {
        use crate::github_source::{PetalAuthorityRoute, PreinstalledPetal};
        static ROUTES: &[PetalAuthorityRoute] = &[
            PetalAuthorityRoute {
                route_id: "r000008",
                operation_classes: &["hyperliquid.builder_order"],
            },
            PetalAuthorityRoute {
                route_id: "r000014",
                operation_classes: &["hyperliquid.agent_action"],
            },
        ];
        // A successor of the real pin: enrollment refuses a package whose
        // hash is not the lineage baseline unless it advances the sequence
        // and lists that baseline, and then records the baseline inactive
        // beside it. Only the synthetic package carries the routes above.
        const SYNTHETIC_HASH: &str =
            "abababababababababababababababababababababababababababababababab";
        // Master's lineage grows whenever a release ships — #224 added
        // hyperliquid v0.1.7 — so the synthetic successor is derived from
        // whatever the lineage holds now instead of pinning its length or its
        // hashes. An earlier version of this test destructured a single
        // baseline and broke the moment that release landed.
        let lineage = crate::github_source::release_lineage_predecessors("hyperliquid");
        let (Some(baseline), Some(newest)) = (lineage.first(), lineage.last()) else {
            panic!("hyperliquid's lineage must hold at least its baseline");
        };
        let predecessors: &'static [&'static str] =
            Vec::leak(lineage.iter().map(|past| past.hash).collect::<Vec<_>>());
        let current = crate::github_source::preinstalled_petal("hyperliquid").unwrap();
        let pin = PreinstalledPetal {
            expected_hash: Some(SYNTHETIC_HASH),
            release_sequence: newest.release_sequence + 1,
            predecessor_package_hashes: predecessors,
            authority_routes: ROUTES,
            ..*current
        };
        assert_eq!(pin.predecessor_package_hashes.first(), Some(&baseline.hash));
        assert_eq!(pin.predecessor_package_hashes.len(), lineage.len());

        let catalog = release_catalog_for(&[&pin]);
        let by_route = catalog
            .records
            .iter()
            .filter_map(|record| {
                let ProvenanceSubject::Petal {
                    package_hash,
                    route,
                } = &record.subject
                else {
                    panic!("release pins only enroll Petal subjects");
                };
                (package_hash.as_str() == SYNTHETIC_HASH)
                    .then_some((route.as_str(), &record.operation_classes))
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(by_route.len(), 2);

        let builder = &by_route["r000008"];
        assert_eq!(builder.len(), 1);
        assert_eq!(
            builder[0].operation_class.as_str(),
            "hyperliquid.builder_order"
        );
        let fee = builder[0]
            .fee_asset
            .as_ref()
            .expect("builder orders are catalogued fee-bearing on the release path");
        assert_eq!(fee.chain.as_str(), "hyperliquid");
        assert_eq!(fee.asset, "usdc");

        let shared = &by_route["r000014"];
        assert_eq!(
            shared[0].operation_class.as_str(),
            "hyperliquid.agent_action"
        );
        assert!(shared[0].fee_asset.is_none());
    }

    /// The real pins carry none of the catalogued builder-order classes yet,
    /// so no release record is fee-bearing today. This fails the moment a pin
    /// is updated for bloom-petal-hyperliquid#19 or the Polymarket route
    /// split, which is the reminder to flip that venue over to asserting its
    /// class is present with the fee asset catalogued above.
    #[test]
    fn current_release_pins_carry_no_fee_bearing_class_yet() {
        let catalog = release_catalog_for(&crate::github_source::release_lineage_petals());
        let classes = catalog
            .records
            .iter()
            .flat_map(|record| record.operation_classes.iter())
            .collect::<Vec<_>>();
        assert!(!classes.is_empty());
        // Named check first. A pin listing a catalogued class is the only way
        // this tripwire fires, and it would also trip the blanket assertion
        // below — which prints nothing useful, so it must not run first.
        for catalogued in FEE_BEARING_OPERATION_CLASSES {
            assert!(
                classes
                    .iter()
                    .all(|class| class.operation_class.as_str() != catalogued.operation_class),
                "the pins now list {}: assert it fee-bearing here",
                catalogued.operation_class
            );
        }
        assert!(
            classes.iter().all(|class| class.fee_asset.is_none()),
            "a pinned class carries a fee asset without being in \
             FEE_BEARING_OPERATION_CLASSES, so enrollment and the table disagree"
        );
    }

    #[cfg(feature = "triad-dev-harness")]
    fn hyperliquid_derivation_route(classes: &[&str]) -> bloom_petals::package::RouteIndexRecord {
        bloom_petals::package::RouteIndexRecord {
            route_id: "r000026".into(),
            pattern: "agent_sessions/[wallet]/new.json".into(),
            source_path: "petal/fixture/new.json.wasm".into(),
            artifact_path: "artifacts/routes/r000026.wasm".into(),
            artifact_hash: "00".repeat(32),
            abi: bloom_petals::package::RouteAbi::ComponentBloomRoute010,
            kind: bloom_petals::package::RouteEntryKind::File,
            ops: vec![bloom_petals::package::RouteOp::Write],
            params: vec!["wallet".into()],
            specificity: [1, 1, 1],
            install_metadata: bloom_petals::package::InstallRouteMetadata {
                mode: 0o644,
                cache_ttl_ms: None,
                side_effecting_read: false,
                write_async: true,
                executable: false,
                required_caps: vec!["bloom:key.derive".into()],
                sign_intent: None,
            },
            key_derive_operation_classes: classes.iter().map(|c| (*c).to_owned()).collect(),
            key_derive_allowed_routes: vec!["r000026".into()],
            key_derive_scope_declared: true,
            key_derive_allowed_crypto_suites: vec!["secp256k1-keccak256-recoverable".into()],
            key_derive_maximum_lifetime_ms: Some(1_800_000),
        }
    }

    /// Broker denies a `DeclaredFee::None` claim with `FEE_REQUIRED` whenever
    /// its class is catalogued with a fee asset. Hyperliquid signs cancels,
    /// leverage updates, and plain orders under `hyperliquid.agent_action`
    /// with `{"kind":"none"}`, so enrolling that shared class as fee-bearing
    /// would deny all of them. Pin it to `None` here so the coarse class can
    /// never be marked fee-bearing again without this failing first.
    #[cfg(feature = "triad-dev-harness")]
    #[test]
    fn developer_route_provenance_leaves_the_shared_agent_action_class_fee_free() {
        let route = hyperliquid_derivation_route(&["hyperliquid.agent_action"]);
        let records = developer_route_operation_classes(&route).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].operation_class.as_str(),
            "hyperliquid.agent_action"
        );
        assert!(records[0].fee_asset.is_none());
    }

    /// Builder-bearing orders are the one Hyperliquid claim that declares a
    /// fee, and they sign under their own class. Broker refuses a
    /// fee-declaring claim in a fee-free class with `FEE_NOT_ALLOWED`, so
    /// that class must be enrolled with the usdc fee asset the Petal
    /// declares, while the shared class it is derived alongside stays free.
    #[cfg(feature = "triad-dev-harness")]
    #[test]
    fn developer_route_provenance_marks_only_the_builder_order_class_fee_bearing() {
        let route = hyperliquid_derivation_route(&[
            "hyperliquid.agent_action",
            "hyperliquid.builder_order",
        ]);
        let records = developer_route_operation_classes(&route).unwrap();
        let by_class = records
            .iter()
            .map(|class| (class.operation_class.as_str(), class.fee_asset.as_ref()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(by_class.len(), 2);
        assert!(by_class["hyperliquid.agent_action"].is_none());
        let fee = by_class["hyperliquid.builder_order"].expect("builder orders are fee-bearing");
        assert_eq!(fee.chain.as_str(), "hyperliquid");
        assert_eq!(fee.asset, "usdc");
    }

    /// A record signed with a *different* fee asset for a class this build does
    /// catalogue is the same operational risk as clearing one: it matched its
    /// Petal before the refresh and would not after, with FEE_ASSET_MISMATCH
    /// instead of FEE_NOT_ALLOWED as the only symptom. So it is reported and
    /// left alone, never re-signed on a guess.
    #[cfg(feature = "triad-dev-harness")]
    #[test]
    fn developer_catalog_refresh_warns_instead_of_replacing_a_differing_fee_asset() {
        let root = RefreshRoot::enrolled();
        let catalog_path = &root.catalog_path;
        let mut stale = root.catalog();

        // A catalogued class, signed with a different asset than the table
        // derives for it.
        let builder_class = Token::new(HYPERLIQUID_BUILDER_ORDER_CLASS).unwrap();
        let mut planted = Vec::new();
        for record in &mut stale.records {
            let ProvenanceSubject::Petal {
                package_hash,
                route,
            } = &record.subject
            else {
                continue;
            };
            if record.publisher == Token::new("bloom-release-pins").unwrap() {
                continue;
            }
            let (package_hash, route) = (package_hash.as_str().to_owned(), route.clone());
            if let Some(class) = record.operation_classes.first_mut() {
                class.operation_class = builder_class.clone();
                class.fee_asset = Some(ProvenanceFeeAsset {
                    chain: Token::new("polygon").unwrap(),
                    asset: "pusd".to_owned(),
                });
                planted.push((package_hash, route));
            }
        }
        assert!(
            !planted.is_empty(),
            "the fixture must enroll a developer record"
        );
        let derived = catalogued_fee_asset(builder_class.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(
            derived.chain.as_str(),
            "hyperliquid",
            "must actually differ"
        );
        root.write(&stale);

        let lines = root
            .refresh()
            .expect("a disagreement is reported, not refused");
        let message = lines.join("\n");
        // The warning text names both symptom codes in one literal, so
        // asserting either one discriminates nothing. What has to hold is the
        // per-record diagnostic: the route and class to act on, and both
        // values, so the operator can tell which side is stale.
        let signed = format!(
            "{:?}",
            Some(ProvenanceFeeAsset {
                chain: Token::new("polygon").unwrap(),
                asset: "pusd".to_owned(),
            })
        );
        let derives = format!(
            "{:?}",
            catalogued_fee_asset(builder_class.as_str()).unwrap()
        );
        for (package_hash, route) in &planted {
            let expected = format!(
                "route {route} of package {package_hash} class {} is signed with {signed} \
                 but this build derives {derives}",
                builder_class.as_str(),
            );
            assert!(
                message.contains(&expected),
                "the warning must name the record, the signed value and the derived one, \
                 expected {expected:?} in: {message}"
            );
        }
        // Whole-catalog equality would say nothing here: the refresh does
        // write, because it rebuilds the release-pins records and re-signs
        // every record. What must hold is narrower — the class this build
        // disagrees with keeps exactly the value it was signed with.
        let after: ProvenanceCatalog =
            serde_json::from_slice(&fs::read(catalog_path).unwrap()).unwrap();
        for (package_hash, route) in &planted {
            let record = after
                .records
                .iter()
                .find(|record| {
                    matches!(&record.subject, ProvenanceSubject::Petal { package_hash: hash, route: found }
                        if hash.as_str() == package_hash && found == route)
                })
                .expect("the refresh must carry the planted record across");
            let class = record
                .operation_classes
                .iter()
                .find(|class| class.operation_class == builder_class)
                .expect("the planted class must survive");
            assert_eq!(
                class.fee_asset,
                Some(ProvenanceFeeAsset {
                    chain: Token::new("polygon").unwrap(),
                    asset: "pusd".to_owned(),
                }),
                "a record this build disagrees with must be left exactly as signed"
            );
        }
    }

    /// A record with no lineage at all stays governed. The launcher's
    /// `jq`-injected authority fixture is exactly that, and its hand-written
    /// `fee_asset` literal has to keep being re-derived. The walk no longer
    /// reads lineage at all, so this is a regression guard against a future
    /// filter reintroducing one and silently dropping this record out of
    /// scope, which nothing else here would notice.
    #[cfg(feature = "triad-dev-harness")]
    #[test]
    fn developer_catalog_refresh_governs_a_record_with_no_lineage() {
        let root = RefreshRoot::enrolled();
        let mut stale = root.catalog();

        // Strip the lineage and plant a conflict the table disagrees with.
        let builder_class = Token::new(HYPERLIQUID_BUILDER_ORDER_CLASS).unwrap();
        let mut planted = 0;
        for record in &mut stale.records {
            if !matches!(record.subject, ProvenanceSubject::Petal { .. })
                || record.publisher == Token::new("bloom-release-pins").unwrap()
            {
                continue;
            }
            record.petal_lineage = None;
            if let Some(class) = record.operation_classes.first_mut() {
                class.operation_class = builder_class.clone();
                class.fee_asset = Some(ProvenanceFeeAsset {
                    chain: Token::new("polygon").unwrap(),
                    asset: "pusd".to_owned(),
                });
                planted += 1;
            }
        }
        assert!(planted > 0, "the fixture must enroll a developer record");
        root.write(&stale);

        let lines = root
            .refresh()
            .expect("a disagreement is reported, not refused");
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("warning:") && line.contains("is signed with")),
            "the warning must name the record: {lines:?}"
        );
    }

    /// A developer-published Petal record the lineage marks superseded,
    /// carrying the class the fixture plants. Both discriminators are needed
    /// to tell one from the inactive predecessor records
    /// `append_release_petal_provenance` contributes; see the call sites.
    #[cfg(feature = "triad-dev-harness")]
    fn planted_predecessor(record: &ProvenanceRecord, builder_class: &Token) -> bool {
        matches!(record.subject, ProvenanceSubject::Petal { .. })
            && record.publisher != Token::new("bloom-release-pins").unwrap()
            && record
                .petal_lineage
                .as_ref()
                .is_some_and(|membership| !membership.active)
            && record
                .operation_classes
                .iter()
                .any(|class| &class.operation_class == builder_class)
    }

    /// A predecessor package stays in the catalog, re-signed inactive. The walk
    /// does not read lineage, so this record is reached like any other — and
    /// because it carries a value, it is reported and left exactly as signed.
    /// Re-enrolment cannot clear it (enrolment only re-derives the package hash
    /// on disk), so recreating the root is the only remedy, and a warning is
    /// the right weight for something no claim can reach anyway.
    #[cfg(feature = "triad-dev-harness")]
    #[test]
    fn developer_catalog_refresh_never_overwrites_an_inactive_package() {
        let root = RefreshRoot::enrolled();
        let catalog_path = &root.catalog_path;
        let mut stale = root.catalog();

        // The same conflict the replace test plants, on a record enrolment has
        // since superseded.
        let builder_class = Token::new(HYPERLIQUID_BUILDER_ORDER_CLASS).unwrap();
        let mut retired = 0;
        for record in &mut stale.records {
            if !matches!(record.subject, ProvenanceSubject::Petal { .. })
                || record.publisher == Token::new("bloom-release-pins").unwrap()
            {
                continue;
            }
            let Some(membership) = record.petal_lineage.as_mut() else {
                continue;
            };
            membership.active = false;
            if let Some(class) = record.operation_classes.first_mut() {
                class.operation_class = builder_class.clone();
                class.fee_asset = Some(ProvenanceFeeAsset {
                    chain: Token::new("polygon").unwrap(),
                    asset: "pusd".to_owned(),
                });
                retired += 1;
            }
        }
        assert!(
            retired > 0,
            "the fixture must enroll a record with a lineage"
        );
        assert!(
            catalogued_fee_asset(builder_class.as_str())
                .unwrap()
                .is_some(),
            "the planted class must be one the table catalogues, or this proves nothing"
        );

        // Captured before the refresh so the check below compares identities
        // and not just a count. Every consumer of a predecessor keys on
        // identity: `check_activation` finds one by its subject package hash,
        // and `carry_private_store` additionally requires the publisher and
        // `lineage_id` to match before it will carry. A refresh that
        // re-pointed a subject hash, or rewrote a publisher, would therefore
        // drop the predecessor for both of them while leaving any count
        // intact — and `carry_private_store` fails quietly there, returning
        // "different_lineage" rather than an error. Serialized rather than
        // cloned because these types are only guaranteed `Serialize` here.
        let planted = stale
            .records
            .iter()
            .filter(|record| planted_predecessor(record, &builder_class))
            .map(|record| {
                (
                    serde_jcs::to_vec(&record.subject).unwrap(),
                    serde_jcs::to_vec(&record.publisher).unwrap(),
                    serde_jcs::to_vec(&record.petal_lineage).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        root.write(&stale);

        let lines = root
            .refresh()
            .expect("an inactive package must not refuse the refresh");
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("warning:") && line.contains("left as signed")),
            "an inactive record this build disagrees with must still be reported, \
             because it is the one case re-enrolment cannot fix: {lines:?}"
        );

        // And it is left exactly as it was, not healed and not rewritten.
        let after: ProvenanceCatalog =
            serde_json::from_slice(&fs::read(catalog_path).unwrap()).unwrap();

        // Still present, and still marked superseded. Asserting only that the
        // record is unmodified would pass vacuously if the refresh dropped it
        // or cleared its lineage, and a dropped predecessor fails an install:
        // `check_activation` needs it, and the private-state carry-forward
        // refuses to carry without it.
        //
        // The filter holds the count to what the fixture planted.
        // `append_release_petal_provenance` adds inactive predecessor records
        // of its own, many more than the fixture plants, so a bare existence
        // probe would pass on those alone — whereas an unfiltered count fails
        // loudly rather than quietly. Either discriminator suffices today,
        // since no release route declares the builder class; they are kept as
        // a pair so adding one later cannot silently widen this count.
        let carried = after
            .records
            .iter()
            .filter(|record| planted_predecessor(record, &builder_class))
            .count();
        assert_eq!(
            carried, retired,
            "every inactive record the fixture planted must survive the refresh, \
             still carrying the lineage that marks it superseded"
        );

        for (subject, publisher, lineage) in &planted {
            let record = after
                .records
                .iter()
                .find(|record| &serde_jcs::to_vec(&record.subject).unwrap() == subject)
                .expect(
                    "the refresh must carry every planted predecessor across \
                     under its own subject, or `check_activation` fails the install",
                );
            assert_eq!(
                &serde_jcs::to_vec(&record.publisher).unwrap(),
                publisher,
                "a carried predecessor must keep its publisher, or \
                 `carry_private_store` stops recognising it and silently \
                 declines to carry the Petal's private state"
            );
            assert_eq!(
                &serde_jcs::to_vec(&record.petal_lineage).unwrap(),
                lineage,
                "a carried predecessor must keep its lineage, `lineage_id` included"
            );
        }

        for record in &after.records {
            let Some(membership) = &record.petal_lineage else {
                continue;
            };
            if membership.active {
                continue;
            }
            for class in &record.operation_classes {
                if class.operation_class == builder_class {
                    assert_eq!(
                        class.fee_asset,
                        Some(ProvenanceFeeAsset {
                            chain: Token::new("polygon").unwrap(),
                            asset: "pusd".to_owned(),
                        }),
                        "an inactive record must be carried across untouched"
                    );
                }
            }
        }
    }

    /// Clearing a fee asset for a class this build does not catalogue would
    /// deny that Petal's claims with FEE_NOT_ALLOWED, so the refresh reports it
    /// and names the recovery rather than rewriting the record.
    #[cfg(feature = "triad-dev-harness")]
    #[test]
    fn developer_catalog_refresh_warns_instead_of_clearing_an_uncatalogued_fee_asset() {
        let root = RefreshRoot::enrolled();
        let output = &root.config;
        let catalog_path = &root.catalog_path;
        let mut stale = root.catalog();

        // A fee asset for a class the table does not know: what an older
        // binary, or a hand edit, could leave behind.
        let mut planted = Vec::new();
        for record in &mut stale.records {
            let ProvenanceSubject::Petal {
                package_hash,
                route,
            } = &record.subject
            else {
                continue;
            };
            if record.publisher == Token::new("bloom-release-pins").unwrap() {
                continue;
            }
            let (package_hash, route) = (package_hash.as_str().to_owned(), route.clone());
            if let Some(class) = record.operation_classes.first_mut() {
                assert!(
                    catalogued_fee_asset(class.operation_class.as_str())
                        .unwrap()
                        .is_none(),
                    "the fixture class must be uncatalogued for this test to mean anything"
                );
                class.fee_asset = Some(ProvenanceFeeAsset {
                    chain: Token::new("hyperliquid").unwrap(),
                    asset: "usdc".to_owned(),
                });
                planted.push((package_hash, route, class.operation_class.clone()));
            }
        }
        assert!(
            !planted.is_empty(),
            "the fixture must enroll a developer record"
        );
        root.write(&stale);

        let lines = root
            .refresh()
            .expect("a disagreement is reported, not refused");
        let message = lines.join("\n");
        // Both symptom codes live in one literal, so neither one on its own
        // says which conflict fired. The diagnostic does: a clear derives
        // None, where a replace derives Some.
        let signed = format!(
            "{:?}",
            Some(ProvenanceFeeAsset {
                chain: Token::new("hyperliquid").unwrap(),
                asset: "usdc".to_owned(),
            })
        );
        for (package_hash, route, class) in &planted {
            let expected = format!(
                "route {route} of package {package_hash} class {} is signed with {signed} \
                 but this build derives None",
                class.as_str(),
            );
            assert!(
                message.contains(&expected),
                "the warning must name the record and show the value that was kept, \
                 expected {expected:?} in: {message}"
            );
        }
        assert!(
            message.contains("FEE_BEARING_OPERATION_CLASSES"),
            "the warning must name the recovery that keeps the claims working: {message}"
        );
        assert!(
            message.contains("re-enrol that Petal to re-derive its records from the table"),
            "the warning must name the targeted recovery, which does re-derive the record: \
             {message}"
        );
        assert!(
            message.contains("left as signed"),
            "the warning must say the record was kept, because the operator is told to go \
             and change one of the two sides: {message}"
        );
        // Naming the remedy is not giving it. The subcommand that fixes this is
        // `hide = true`, so `--help` does not list it, and the launcher does
        // not run it: this message is the operator's only output.
        for fragment in [
            "cargo build -p bloom --no-default-features --features mount,triad-dev-harness",
            "target/debug/bloom init triad-enroll-developer-petal-provenance",
            "<petal-package-dir>",
        ] {
            assert!(
                message.contains(fragment),
                "the warning must carry a runnable recovery command, missing \
                 {fragment:?} in: {message}"
            );
        }
        assert!(
            message.contains(&output.display().to_string()),
            "the command must name this root's own config directory rather than a \
             placeholder the operator has to resolve: {message}"
        );

        // And it must leave the record alone rather than half-rewriting it.
        // Not whole-catalog equality: the refresh does write, because it
        // rebuilds the release-pins records and re-signs every record. The
        // narrower claim is the one that matters.
        let after: ProvenanceCatalog =
            serde_json::from_slice(&fs::read(catalog_path).unwrap()).unwrap();
        for (package_hash, route, class_name) in &planted {
            let record = after
                .records
                .iter()
                .find(|record| {
                    matches!(&record.subject, ProvenanceSubject::Petal { package_hash: hash, route: found }
                        if hash.as_str() == package_hash && found == route)
                })
                .expect("the refresh must carry the planted record across");
            let class = record
                .operation_classes
                .iter()
                .find(|class| &class.operation_class == class_name)
                .expect("the planted class must survive");
            assert_eq!(
                class.fee_asset,
                Some(ProvenanceFeeAsset {
                    chain: Token::new("hyperliquid").unwrap(),
                    asset: "usdc".to_owned(),
                }),
                "a class this build does not catalogue must keep the value it was signed \
                 with, or its claims start failing FEE_NOT_ALLOWED"
            );
        }
    }

    /// A developer root enrolled before a class was catalogued carries its
    /// records across the refresh verbatim. Without re-deriving the fee asset
    /// the stale `None` survives, re-signed and valid, and every builder order
    /// is denied FEE_NOT_ALLOWED on a Bloom that looks correct.
    #[cfg(feature = "triad-dev-harness")]
    #[test]
    fn developer_catalog_refresh_rederives_a_stale_fee_asset() {
        const LEGACY_COMPONENT: &str = "bloom-legacy-component";
        let root = RefreshRoot::enrolled();
        let catalog_path = &root.catalog_path;
        let read = || -> ProvenanceCatalog {
            serde_json::from_slice(&fs::read(catalog_path).unwrap()).unwrap()
        };

        // What an older binary wrote: the fee-bearing class, enrolled fee-free
        // because no table existed to catalogue it.
        let builder_class = Token::new(HYPERLIQUID_BUILDER_ORDER_CLASS).unwrap();
        let mut stale = read();
        let mut rewritten = 0;
        for record in &mut stale.records {
            if matches!(record.subject, ProvenanceSubject::Petal { .. })
                && record.publisher != Token::new("bloom-release-pins").unwrap()
                && let Some(class) = record.operation_classes.first_mut()
            {
                class.operation_class = builder_class.clone();
                class.fee_asset = None;
                rewritten += 1;
            }
        }
        assert!(rewritten > 0, "the fixture must enroll a developer record");

        // A System subject the current template does not list, so the refresh
        // carries it instead of replacing it from the template.
        let mut renamed = 0;
        for record in &mut stale.records {
            // The fee asset lives in `operation_classes`; the subject's own
            // `operation_class` is a different token (`solana.transfer.confirm`).
            if record
                .operation_classes
                .iter()
                .any(|class| class.operation_class.as_str() == "solana.native-transfer")
                && let ProvenanceSubject::System { component_id, .. } = &mut record.subject
            {
                *component_id = Token::new(LEGACY_COMPONENT).unwrap();
                renamed += 1;
            }
        }
        assert_eq!(renamed, 1, "the template must ship one native-transfer row");
        root.write(&stale);

        let notes = root.refresh().unwrap();
        assert_eq!(
            notes.len(),
            rewritten,
            "a heal that was written must be announced, once per record: {notes:?}"
        );
        assert!(
            notes
                .iter()
                .all(|note| note.contains(HYPERLIQUID_BUILDER_ORDER_CLASS)),
            "a note must name the class whose fee asset it re-derived: {notes:?}"
        );
        let refreshed = read();
        refreshed.validate_shape().unwrap();

        let release_publisher = Token::new("bloom-release-pins").unwrap();
        let mut healed = 0;
        for record in &refreshed.records {
            // Release records are rebuilt from the pins, not carried, so they
            // are not what this counts. Including them would make the test
            // fail the moment a pin lists a catalogued class, which is exactly
            // what releasing bloom-petal-hyperliquid#19 does.
            if record.publisher == release_publisher {
                continue;
            }
            for class in &record.operation_classes {
                if class.operation_class == builder_class {
                    let fee = class
                        .fee_asset
                        .as_ref()
                        .expect("the refresh must re-derive a catalogued fee asset");
                    assert_eq!(fee.chain.as_str(), "hyperliquid");
                    assert_eq!(fee.asset, "usdc");
                    healed += 1;
                }
            }
        }
        assert_eq!(healed, rewritten, "every stale record must be re-derived");

        // The carve-out the Petal guard provides: a System subject this
        // template no longer lists is carried over like a developer record,
        // and must keep the fee asset it was signed with rather than being
        // re-derived from a table that does not govern it. Asserting the
        // template's own System row proves nothing — it is re-added verbatim
        // on every refresh whatever this loop does.
        let legacy_fee = refreshed
            .records
            .iter()
            .filter(|record| matches!(&record.subject, ProvenanceSubject::System { component_id, .. } if component_id.as_str() == LEGACY_COMPONENT))
            .flat_map(|record| &record.operation_classes)
            .find(|class| class.operation_class.as_str() == "solana.native-transfer")
            .and_then(|class| class.fee_asset.as_ref())
            .expect("a carried legacy System record must survive the refresh");
        assert_eq!(legacy_fee.chain.as_str(), "solana");
        assert_eq!(legacy_fee.asset, "native");
    }

    /// One record, both halves: a catalogued class with no value, and an
    /// uncatalogued class carrying one. The heal must land and the
    /// disagreement must be reported, in the same pass.
    ///
    /// This is the case the earlier refusing design got wrong in both
    /// directions. It walked the whole catalog before deciding, so the heal was
    /// always reached and always thrown away — and the refusal then told the
    /// operator to read notes describing a change that had not been written.
    /// Neither half happened: a root needing a legitimate heal on one class
    /// while holding a disagreement on another got nothing, and no launch.
    #[cfg(feature = "triad-dev-harness")]
    #[test]
    fn a_disagreement_warns_without_blocking_the_heal_beside_it() {
        let root = RefreshRoot::enrolled();
        let catalog_path = &root.catalog_path;
        let mut stale = root.catalog();

        // One record carrying both halves: a catalogued class with no value,
        // which the walk heals in memory, and an uncatalogued class carrying
        // one, which makes the walk refuse. The refusal lands only after every
        // record has been walked, so the heal is always reached, and always
        // thrown away.
        let builder_class = Token::new(HYPERLIQUID_BUILDER_ORDER_CLASS).unwrap();
        let mut planted = 0;
        let mut uncatalogued = None;
        for record in &mut stale.records {
            if !matches!(record.subject, ProvenanceSubject::Petal { .. })
                || record.publisher == Token::new("bloom-release-pins").unwrap()
            {
                continue;
            }
            let Some(class) = record.operation_classes.first_mut() else {
                continue;
            };
            assert!(
                catalogued_fee_asset(class.operation_class.as_str())
                    .unwrap()
                    .is_none(),
                "the fixture class must be uncatalogued for the conflict half to bite"
            );
            uncatalogued = Some(class.operation_class.clone());
            class.fee_asset = Some(ProvenanceFeeAsset {
                chain: Token::new("hyperliquid").unwrap(),
                asset: "usdc".to_owned(),
            });
            record.operation_classes.insert(
                0,
                ProvenanceOperationClass {
                    operation_class: builder_class.clone(),
                    fee_asset: None,
                },
            );
            planted += 1;
        }
        assert!(planted > 0, "the fixture must enroll a developer record");
        let uncatalogued = uncatalogued.expect("the fixture must carry an uncatalogued class");
        root.write(&stale);
        let before = fs::read(catalog_path).unwrap();

        let lines = root
            .refresh()
            .expect("a disagreement on one class must not block the heal on another");

        // Both halves, and each announced as what it is.
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("note:")
                    && line.contains(HYPERLIQUID_BUILDER_ORDER_CLASS)),
            "the heal must be announced as a saved change: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.starts_with("warning:")
                && line.contains(uncatalogued.as_str())
                && line.contains("left as signed")),
            "the disagreement must be announced as one, not as a change: {lines:?}"
        );

        // A note must describe something written, so the catalog has to have
        // moved — the half the refusing design announced and then discarded.
        assert_ne!(
            fs::read(catalog_path).unwrap(),
            before,
            "the heal must reach disk, not just the notes"
        );
        let after: ProvenanceCatalog =
            serde_json::from_slice(&fs::read(catalog_path).unwrap()).unwrap();
        let mut healed = 0;
        let mut kept = 0;
        for record in &after.records {
            for class in &record.operation_classes {
                if class.operation_class == builder_class {
                    assert_eq!(
                        class.fee_asset,
                        catalogued_fee_asset(builder_class.as_str()).unwrap(),
                        "the catalogued class must be healed to the table's value"
                    );
                    healed += 1;
                } else if class.operation_class == uncatalogued {
                    assert_eq!(
                        class.fee_asset,
                        Some(ProvenanceFeeAsset {
                            chain: Token::new("hyperliquid").unwrap(),
                            asset: "usdc".to_owned(),
                        }),
                        "the class this build does not catalogue must keep what it was \
                         signed with, or its claims start failing FEE_NOT_ALLOWED"
                    );
                    kept += 1;
                }
            }
        }
        assert_eq!(healed, planted, "every planted heal must have landed");
        assert_eq!(
            kept, planted,
            "every planted disagreement must have been kept"
        );
    }

    #[cfg(feature = "triad-dev-harness")]
    #[test]
    fn developer_catalog_refresh_replaces_stale_release_pins_and_keeps_developer_records() {
        let _fixture = FIXTURE_PETAL
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("config");
        fs::create_dir(&output).unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        let owner = rustix::process::geteuid().as_raw();
        let plan = EnrollmentPlan {
            template_dir: template_dir(),
            output_dir: output.clone(),
            login_uid: 1_001,
            broker_uid: 1_002,
            signer_uid: 1_003,
            session_socket_gid: 1_004,
            release_digest: "44".repeat(32),
        };
        generate_for_owner(&plan, owner).unwrap();
        let petal_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join("tests/fixtures/triad-authority-petal");
        let developer_hash = PreparedPetalPackage::from_dir(&petal_dir).unwrap().hash;
        enroll_developer_petal_provenance(&output, &petal_dir, owner).unwrap();
        let catalog_path = output.join("provenance-catalog.json");
        let read = || -> ProvenanceCatalog {
            serde_json::from_slice(&fs::read(&catalog_path).unwrap()).unwrap()
        };
        let developer_records = |catalog: &ProvenanceCatalog| -> Vec<ProvenanceRecord> {
            catalog
                .records
                .iter()
                .filter(|record| matches!(&record.subject,
                    ProvenanceSubject::Petal { package_hash, .. } if package_hash.as_str() == developer_hash))
                .cloned()
                .collect()
        };
        let enrolled = developer_records(&read());
        assert!(!enrolled.is_empty());

        // Simulate a developer root created by an older binary: its release
        // pins name a package this binary no longer ships.
        let (signing_key, installer_key_id) = load_developer_installer(&output).unwrap();
        let mut stale = read();
        let release_publisher = Token::new("bloom-release-pins").unwrap();
        stale
            .records
            .retain(|record| record.publisher != release_publisher);
        let stale_hash = Digest32::new("ab".repeat(32)).unwrap();
        append_release_lineage_record(
            &mut stale,
            &signing_key,
            &installer_key_id,
            &release_publisher,
            &release_petal_lineage_id(&release_publisher, "polymarket"),
            &stale_hash,
            1,
            &[],
            true,
            &[],
        )
        .unwrap();
        rewrite_private_json(&catalog_path, &serde_json::to_value(&stale).unwrap()).unwrap();

        refresh_developer_provenance_catalog(
            &template_dir().join("provenance-catalog.unsigned.json"),
            &output,
            owner,
        )
        .unwrap();
        let refreshed = read();
        refreshed.validate_shape().unwrap();
        assert_eq!(developer_records(&refreshed), enrolled);
        let active_hashes: Vec<&str> = refreshed
            .records
            .iter()
            .filter(|record| record.petal_lineage.as_ref().is_some_and(|l| l.active))
            .filter_map(|record| match &record.subject {
                ProvenanceSubject::Petal { package_hash, .. } => Some(package_hash.as_str()),
                _ => None,
            })
            .collect();
        assert!(!active_hashes.contains(&stale_hash.as_str()));
        for pinned in crate::github_source::release_lineage_petals() {
            assert!(
                active_hashes.contains(&pinned.expected_hash.unwrap()),
                "{}",
                pinned.name
            );
        }
        let verifier = signing_key.verifying_key();
        for record in &refreshed.records {
            let mut message = PROVENANCE_RECORD_SIGNATURE_DOMAIN.to_vec();
            message.extend_from_slice(&record.unsigned_canonical_bytes().unwrap());
            let signature: [u8; 64] = record.installer_signature.decode().try_into().unwrap();
            verifier
                .verify(&message, &Signature::from_bytes(&signature))
                .unwrap();
        }

        // An up-to-date catalog is left untouched.
        let before = fs::read(&catalog_path).unwrap();
        let inode = fs::metadata(&catalog_path).unwrap().ino();
        refresh_developer_provenance_catalog(
            &template_dir().join("provenance-catalog.unsigned.json"),
            &output,
            owner,
        )
        .unwrap();
        assert_eq!(fs::read(&catalog_path).unwrap(), before);
        assert_eq!(fs::metadata(&catalog_path).unwrap().ino(), inode);
    }

    #[cfg(feature = "triad-dev-harness")]
    #[test]
    fn enrolled_linux_petal_satisfies_the_machine_active_lineage_gate() {
        let _fixture = FIXTURE_PETAL
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        validate_developer_caller(1000, "linux").unwrap();
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("config");
        fs::create_dir(&output).unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        let owner = rustix::process::geteuid().as_raw();
        let plan = EnrollmentPlan {
            template_dir: template_dir(),
            output_dir: output.clone(),
            login_uid: 1_001,
            broker_uid: 1_002,
            signer_uid: 1_003,
            session_socket_gid: 1_004,
            release_digest: "44".repeat(32),
        };
        generate_for_owner(&plan, owner).unwrap();
        let petal_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join("tests/fixtures/triad-authority-petal");
        let package = PreparedPetalPackage::from_dir(&petal_dir).unwrap();

        enroll_developer_petal_provenance(&output, &petal_dir, owner).unwrap();
        let first: ProvenanceCatalog =
            serde_json::from_slice(&fs::read(output.join("provenance-catalog.json")).unwrap())
                .unwrap();
        first.validate_shape().unwrap();
        let records = first
            .records
            .iter()
            .filter(|record| {
                matches!(
                    &record.subject,
                    ProvenanceSubject::Petal { package_hash, .. }
                        if package_hash.as_str() == package.hash
                )
            })
            .collect::<Vec<_>>();
        assert!(!records.is_empty());
        let membership = records[0].petal_lineage.as_ref().unwrap();
        assert!(membership.active);
        assert_eq!(membership.release_sequence.get(), 1);
        assert!(membership.predecessor_package_hashes.is_empty());
        assert!(!membership.controller_signature.decode().is_empty());
        assert!(records.iter().all(|record| {
            record
                .petal_lineage
                .as_ref()
                .filter(|value| value.active)
                .is_some()
        }));
        assert!(
            records
                .iter()
                .all(|record| record.petal_lineage.as_ref() == Some(membership))
        );
        assert_eq!(records.len(), 1);
        let operation_classes = records[0]
            .operation_classes
            .iter()
            .map(|class| class.operation_class.as_str())
            .collect::<Vec<_>>();
        assert_eq!(operation_classes, ["fixture.payload"]);
        assert!(!operation_classes.contains(&"fixture.unrelated"));
        let installer: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("installer-identity.json")).unwrap())
                .unwrap();
        let public: [u8; 32] = hex::decode(installer["public_key_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let verifier = VerifyingKey::from_bytes(&public).unwrap();
        for record in &records {
            let signature: [u8; 64] = record.installer_signature.decode().try_into().unwrap();
            let mut message = PROVENANCE_RECORD_SIGNATURE_DOMAIN.to_vec();
            message.extend_from_slice(&record.unsigned_canonical_bytes().unwrap());
            verifier
                .verify(&message, &Signature::from_bytes(&signature))
                .unwrap();
        }
        let ProvenanceSubject::Petal { package_hash, .. } = &records[0].subject else {
            unreachable!();
        };
        let mut controller_message = DEVELOPER_PETAL_LINEAGE_DOMAIN.to_vec();
        controller_message.extend_from_slice(
            &serde_jcs::to_vec(&DeveloperPetalLineageStatement {
                schema: "bloom.developer-petal-lineage.1",
                lineage_id: &membership.lineage_id,
                package_hash,
                release_sequence: membership.release_sequence.clone(),
                predecessor_package_hashes: &membership.predecessor_package_hashes,
                controller_key_id: &membership.controller_key_id,
                publisher: &records[0].publisher,
                active: membership.active,
            })
            .unwrap(),
        );
        let signature: [u8; 64] = membership.controller_signature.decode().try_into().unwrap();
        verifier
            .verify(&controller_message, &Signature::from_bytes(&signature))
            .unwrap();

        enroll_developer_petal_provenance(&output, &petal_dir, owner).unwrap();
        let second: ProvenanceCatalog =
            serde_json::from_slice(&fs::read(output.join("provenance-catalog.json")).unwrap())
                .unwrap();
        let second_membership = second
            .records
            .iter()
            .find_map(|record| match &record.subject {
                ProvenanceSubject::Petal { package_hash, .. }
                    if package_hash.as_str() == package.hash =>
                {
                    record.petal_lineage.as_ref()
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(second_membership, membership);
    }

    #[test]
    fn bundled_successor_retains_inactive_baseline_for_state_carry_forward() {
        let signing = SigningKey::from_bytes(&[17; 32]);
        let key_id = Token::new("installer-key").unwrap();
        for (name, baseline_hash) in [
            (
                "enso",
                "97650f327691f01bc4591cde25253d1e20010643e700674cc9759cd1366876b9",
            ),
            (
                "near-intents",
                "ac2ccab59f36ee863843f92aaf0c975c00dbf32b246df5ccbb79757093785921",
            ),
            (
                "polymarket",
                "5df5a1377dc4d70c71e47ffe6827e691e1f5868543b752dc8d19a500284e5fa6",
            ),
            (
                "hyperliquid",
                "b29c7afb88ec9d2df774b18dad2699ec169100eeeedbcefca02ea0cc3712a188",
            ),
            (
                "tolly",
                "f50f9f6f55eca103c11ed40d424311c6e5863ff5046231f57f58822d1aac6709",
            ),
        ] {
            let current = crate::github_source::preinstalled_petal(name).unwrap();
            let successor = crate::github_source::PreinstalledPetal {
                expected_hash: Some(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                ),
                release_sequence: 2,
                predecessor_package_hashes: match name {
                    "enso" => &["97650f327691f01bc4591cde25253d1e20010643e700674cc9759cd1366876b9"],
                    "near-intents" => {
                        &["ac2ccab59f36ee863843f92aaf0c975c00dbf32b246df5ccbb79757093785921"]
                    }
                    "polymarket" => {
                        &["5df5a1377dc4d70c71e47ffe6827e691e1f5868543b752dc8d19a500284e5fa6"]
                    }
                    "hyperliquid" => {
                        &["b29c7afb88ec9d2df774b18dad2699ec169100eeeedbcefca02ea0cc3712a188"]
                    }
                    _ => &["f50f9f6f55eca103c11ed40d424311c6e5863ff5046231f57f58822d1aac6709"],
                },
                ..*current
            };
            let mut catalog = ProvenanceCatalog {
                schema: bloom_broker_api::PROVENANCE_CATALOG_SCHEMA.into(),
                records: vec![],
            };
            append_release_petal_provenance_for_entries(
                &mut catalog,
                &key_id,
                &signing,
                &[&successor],
            )
            .unwrap();
            let old = catalog.records.iter().find(|record| matches!(
                &record.subject,
                ProvenanceSubject::Petal { package_hash, .. } if package_hash.as_str() == baseline_hash
            )).unwrap();
            let new = catalog.records.iter().find(|record| matches!(
                &record.subject,
                ProvenanceSubject::Petal { package_hash, .. } if package_hash.as_str() == successor.expected_hash.unwrap()
            )).unwrap();
            let old_lineage = old.petal_lineage.as_ref().unwrap();
            let new_lineage = new.petal_lineage.as_ref().unwrap();
            assert!(!old_lineage.active);
            assert_eq!(old_lineage.release_sequence.get(), 1);
            assert!(new_lineage.active);
            assert_eq!(new_lineage.release_sequence.get(), 2);
            assert_eq!(old_lineage.lineage_id, new_lineage.lineage_id);
            assert_eq!(old.publisher, new.publisher);
            assert!(
                new_lineage
                    .predecessor_package_hashes
                    .iter()
                    .any(|hash| hash.as_str() == baseline_hash)
            );
            if !matches!(name, "polymarket" | "hyperliquid") {
                assert!(old.operation_classes.is_empty());
                assert!(new.operation_classes.is_empty());
            }
        }
    }

    // Upgrading from Bloom v0.4.0 (Polymarket v0.1.6) failed with "predecessor
    // release information is missing" because only the baseline was recorded.
    #[test]
    fn release_catalog_records_every_listed_predecessor() {
        let mut catalog = ProvenanceCatalog {
            schema: bloom_broker_api::PROVENANCE_CATALOG_SCHEMA.into(),
            records: vec![],
        };
        append_release_petal_provenance(
            &mut catalog,
            &Token::new("installer-key").unwrap(),
            &SigningKey::from_bytes(&[17; 32]),
        )
        .unwrap();
        let lineage = |hash: &str| {
            catalog
                .records
                .iter()
                .find(|record| matches!(
                    &record.subject,
                    ProvenanceSubject::Petal { package_hash, .. } if package_hash.as_str() == hash
                ))
                .and_then(|record| record.petal_lineage.clone())
        };
        for entry in crate::github_source::release_lineage_petals() {
            for hash in entry.predecessor_package_hashes {
                let old = lineage(hash)
                    .unwrap_or_else(|| panic!("{} predecessor {hash} missing", entry.name));
                assert!(!old.active);
                assert!(old.release_sequence.get() < entry.release_sequence);
            }
        }
        let v016 = lineage("0f365cd7f613129f73ce66fb07256c8a42c4e70abbb77721804dbd6df85b96b5")
            .expect("Polymarket v0.1.6 is in the catalog");
        assert_eq!(v016.release_sequence.get(), 2);
    }

    #[test]
    fn release_catalog_refuses_an_unrecorded_predecessor() {
        let current = crate::github_source::preinstalled_petal("polymarket").unwrap();
        let successor = crate::github_source::PreinstalledPetal {
            expected_hash: Some("1111111111111111111111111111111111111111111111111111111111111111"),
            release_sequence: 4,
            predecessor_package_hashes: &[
                "5df5a1377dc4d70c71e47ffe6827e691e1f5868543b752dc8d19a500284e5fa6",
                "2222222222222222222222222222222222222222222222222222222222222222",
            ],
            ..*current
        };
        let mut catalog = ProvenanceCatalog {
            schema: bloom_broker_api::PROVENANCE_CATALOG_SCHEMA.into(),
            records: vec![],
        };
        let error = append_release_petal_provenance_for_entries(
            &mut catalog,
            &Token::new("installer-key").unwrap(),
            &SigningKey::from_bytes(&[17; 32]),
            &[&successor],
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("has no recorded release"),
            "{error:#}"
        );
    }

    #[test]
    fn generated_material_is_fresh_cross_pinned_and_provenance_signed() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output");
        fs::create_dir(&output).unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        let plan = EnrollmentPlan {
            template_dir: template_dir(),
            output_dir: output.clone(),
            login_uid: 501,
            broker_uid: 250_501,
            signer_uid: 250_502,
            session_socket_gid: 260_503,
            release_digest: "11".repeat(32),
        };
        generate_for_owner(&plan, rustix::process::geteuid().as_raw()).unwrap();

        let edge: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("edge-manifest.json")).unwrap()).unwrap();
        let broker_identity: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("broker-identity.json")).unwrap())
                .unwrap();
        let broker_seed: [u8; 32] =
            hex::decode(broker_identity["private_key_seed_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            edge["broker"]["application_public_key_hex"]
                .as_str()
                .unwrap(),
            hex::encode(
                SigningKey::from_bytes(&broker_seed)
                    .verifying_key()
                    .to_bytes()
            )
        );
        assert_eq!(edge["session_socket_gid"], 260_503);

        let signer_config: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("signer.json")).unwrap()).unwrap();
        let signer_revocation_seed = signer_config["revocation_signing_seed_hex"]
            .as_str()
            .unwrap();
        let signer_audit_seed = signer_config["audit_signing_seed_hex"].as_str().unwrap();
        let signer_ceremony_seed = signer_config["ceremony_signing_seed_hex"].as_str().unwrap();
        assert_ne!(signer_audit_seed, signer_revocation_seed);
        assert_ne!(signer_audit_seed, signer_ceremony_seed);
        assert_ne!(
            signer_config["audit_key_id"],
            signer_config["revocation_key_id"]
        );
        assert_ne!(
            signer_config["audit_key_id"],
            signer_config["ceremony_key_id"]
        );

        let installer: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("installer-identity.json")).unwrap())
                .unwrap();
        let public: [u8; 32] = hex::decode(installer["public_key_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let verifier = VerifyingKey::from_bytes(&public).unwrap();
        let catalog: ProvenanceCatalog =
            serde_json::from_slice(&fs::read(output.join("provenance-catalog.json")).unwrap())
                .unwrap();
        let petal_hashes = catalog
            .records
            .iter()
            .filter_map(|record| match &record.subject {
                ProvenanceSubject::Petal { package_hash, .. } => Some(package_hash.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        // Includes records for the replaced Polymarket v0.1.6 and v0.1.8 (five
        // routes each) and v0.2.0 (six), Hyperliquid v0.1.7 and v0.1.9
        // (sixteen each), Enso v0.1.6 (one) and NEAR Intents v0.1.4 (one).
        assert_eq!(petal_hashes.len(), 99);
        for name in crate::github_source::DEFAULT_PETALS {
            let expected = crate::github_source::preinstalled_petal(name)
                .unwrap()
                .expected_hash
                .unwrap();
            assert!(
                petal_hashes.contains(&expected),
                "missing {name} release provenance"
            );
        }
        // The release-pins path must agree with the developer-harness path:
        // the shared classes stay fee-free, because Broker denies every
        // `DeclaredFee::None` claim in a fee-bearing class with
        // `FEE_REQUIRED`. Assert it over the shared Hyperliquid class and
        // Polymarket's relayer class explicitly. The fee-bearing
        // `hyperliquid.builder_order` class is asserted here only once the
        // Hyperliquid release pin carries its routes; until then the catalog
        // cannot contain it and an assertion would be vacuous. System records
        // are out of scope: a native Solana transfer always pays a network
        // fee, so its template class names one.
        let all_classes = catalog
            .records
            .iter()
            .flat_map(|record| record.operation_classes.iter())
            .collect::<Vec<_>>();
        for class in ["hyperliquid.agent_action", "polymarket.relayer_batch"] {
            let matching = all_classes
                .iter()
                .filter(|entry| entry.operation_class.as_str() == class)
                .collect::<Vec<_>>();
            assert!(!matching.is_empty(), "{class} is absent from the catalog");
            assert!(matching.iter().all(|entry| entry.fee_asset.is_none()));
        }
        for record in catalog.records {
            let mut unsigned = record.clone();
            let signature: [u8; 64] = unsigned.installer_signature.decode().try_into().unwrap();
            unsigned.installer_signature = Base64UrlBytes::from_bytes(&[]);
            let mut message = PROVENANCE_RECORD_SIGNATURE_DOMAIN.to_vec();
            message.extend_from_slice(&serde_jcs::to_vec(&unsigned).unwrap());
            verifier
                .verify(&message, &Signature::from_bytes(&signature))
                .unwrap();
        }
        let refreshed = output.join("provenance-catalog.refreshed.json");
        refresh_provenance_catalog_for_owner(
            &template_dir().join("provenance-catalog.unsigned.json"),
            &output.join("installer-identity.json"),
            &refreshed,
            rustix::process::geteuid().as_raw(),
        )
        .unwrap();
        assert_eq!(
            fs::read(refreshed).unwrap(),
            fs::read(output.join("provenance-catalog.json")).unwrap()
        );
        for name in [
            "machine-identity.json",
            "broker-identity.json",
            "signer-identity.json",
            "revoke-identity.json",
            "session-identity.json",
            "installer-identity.json",
            "broker.json",
            "signer.json",
        ] {
            assert_eq!(
                fs::metadata(output.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn developer_configs_resolve_every_path_beneath_one_root_without_containment() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = fs::canonicalize(directory.path()).unwrap();
        let output = root.join("config");
        fs::create_dir(&output).unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let plan = EnrollmentPlan {
            template_dir: template_dir(),
            output_dir: output.clone(),
            login_uid: 1_001,
            broker_uid: 1_002,
            signer_uid: 1_003,
            session_socket_gid: 1_004,
            release_digest: "33".repeat(32),
        };
        generate_for_owner(&plan, uid).unwrap();
        render_developer_runtime_paths(&output, &root).unwrap();

        let broker: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("broker.json")).unwrap()).unwrap();
        let signer: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("signer.json")).unwrap()).unwrap();
        assert!(broker["network_containment"].is_null());
        assert!(signer["network_containment"].is_null());
        for path in [
            &broker["journal_path"],
            &broker["authority_path"],
            &broker["ceremony_path"],
            &broker["signer_socket_path"],
            &broker["provenance_catalog_path"],
            &signer["database_path"],
        ] {
            let path = Path::new(path.as_str().unwrap());
            assert!(path.is_absolute());
            assert!(
                path.starts_with(&root),
                "{} escaped developer root",
                path.display()
            );
        }
        for name in ["broker.json", "signer.json"] {
            assert!(!fs::read_to_string(output.join(name)).unwrap().contains('@'));
        }
    }

    #[test]
    fn transport_rotation_replaces_every_application_identity_and_cross_pin() {
        let directory = tempfile::tempdir().unwrap();
        let initial = directory.path().join("initial");
        let rotated = directory.path().join("rotated");
        for output in [&initial, &rotated] {
            fs::create_dir(output).unwrap();
            fs::set_permissions(output, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let plan = EnrollmentPlan {
            template_dir: template_dir(),
            output_dir: initial.clone(),
            login_uid: 501,
            broker_uid: 250_501,
            signer_uid: 250_502,
            session_socket_gid: 260_503,
            release_digest: "11".repeat(32),
        };
        let owner = rustix::process::geteuid().as_raw();
        generate_for_owner(&plan, owner).unwrap();
        generate_identity_rotation_for_owner(&initial.join("edge-manifest.json"), &rotated, owner)
            .unwrap();

        let old_edge: serde_json::Value =
            serde_json::from_slice(&fs::read(initial.join("edge-manifest.json")).unwrap()).unwrap();
        let new_edge: serde_json::Value =
            serde_json::from_slice(&fs::read(rotated.join("edge-manifest.json")).unwrap()).unwrap();
        for (edge_name, file_name) in [
            ("machine", "machine-identity.json"),
            ("broker", "broker-identity.json"),
            ("signer", "signer-identity.json"),
            ("revoke_client", "revoke-identity.json"),
            ("session", "session-identity.json"),
        ] {
            assert_ne!(
                old_edge[edge_name]["boot_epoch"],
                new_edge[edge_name]["boot_epoch"]
            );
            let identity: serde_json::Value =
                serde_json::from_slice(&fs::read(rotated.join(file_name)).unwrap()).unwrap();
            let seed: [u8; 32] = hex::decode(
                identity["private_key_seed_hex"]
                    .as_str()
                    .expect("identity seed"),
            )
            .unwrap()
            .try_into()
            .unwrap();
            assert_eq!(
                new_edge[edge_name]["application_public_key_hex"]
                    .as_str()
                    .unwrap(),
                hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
            );
        }
        assert!(!rotated.join("broker.json").exists());
        assert!(!rotated.join("signer.json").exists());
        assert!(!rotated.join("installer-identity.json").exists());
    }
}
