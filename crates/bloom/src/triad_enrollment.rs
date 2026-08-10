//! Root-only generation of per-login macOS triad identities and signing
//! material from public release templates.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use bloom_broker_api::{
    Base64UrlBytes, PROVENANCE_RECORD_SIGNATURE_DOMAIN, ProvenanceCatalog, Token,
};
#[cfg(feature = "triad-dev-harness")]
use bloom_broker_api::{ProvenanceOperationClass, ProvenanceRecord, ProvenanceSubject};
#[cfg(feature = "triad-dev-harness")]
use bloom_petals::package::PreparedPetalPackage;
use ed25519_dalek::{Signer as _, SigningKey};
use rand::{RngCore as _, rngs::OsRng};
#[cfg(feature = "triad-dev-harness")]
use serde::Deserialize;
use serde::Serialize;
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

#[cfg(feature = "triad-dev-harness")]
pub fn run_developer(template_dir: &Path, output_dir: &Path, release_digest: String) -> Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    if uid == 0 {
        bail!("developer enrollment material generation refuses root");
    }
    if std::env::consts::OS != "macos" {
        bail!("developer enrollment material generation requires Darwin");
    }
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
    if uid == 0 {
        bail!("developer Petal provenance enrollment refuses root");
    }
    if std::env::consts::OS != "macos" {
        bail!("developer Petal provenance enrollment is only supported on macOS");
    }
    let config_dir =
        fs::canonicalize(config_dir).context("canonicalize developer triad config directory")?;
    let petal_dir =
        fs::canonicalize(petal_dir).context("canonicalize developer Petal package directory")?;
    enroll_developer_petal_provenance(&config_dir, &petal_dir, uid)
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
    let installer_key_id = Token::new(identity.key_id)?;

    let package = PreparedPetalPackage::from_dir(petal_dir)
        .map_err(|error| anyhow::anyhow!("prepare developer Petal package: {error}"))?;
    let publisher = Token::new("bloom-developer-local-package")?;
    let package_hash = bloom_broker_api::Digest32::new(package.hash.clone())?;
    let mut additions = Vec::new();
    for route in &package.route_index.routes {
        let Some(intent) = route.install_metadata.sign_intent.as_deref() else {
            continue;
        };
        additions.push(ProvenanceRecord {
            subject: ProvenanceSubject::Petal {
                package_hash: package_hash.clone(),
                route: route.route_id.clone(),
            },
            publisher: publisher.clone(),
            operation_classes: vec![ProvenanceOperationClass {
                operation_class: Token::new(intent.to_owned())?,
                fee_asset: None,
            }],
            installer_key_id: installer_key_id.clone(),
            installer_signature: Base64UrlBytes::from_bytes(&[]),
        });
    }
    if additions.is_empty() {
        bail!(
            "developer Petal {} imports signing but declares no route sign intents",
            package.name
        );
    }

    let catalog_path = config_dir.join("provenance-catalog.json");
    let mut catalog: ProvenanceCatalog =
        serde_json::from_slice(&fs::read(&catalog_path)?).context("parse provenance catalog")?;
    catalog.records.retain(|record| {
        !matches!(
            &record.subject,
            ProvenanceSubject::Petal { package_hash: existing, .. } if existing == &package_hash
        )
    });
    for record in &mut additions {
        let mut message = PROVENANCE_RECORD_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&record.unsigned_canonical_bytes()?);
        record.installer_signature =
            Base64UrlBytes::from_bytes(&signing_key.sign(&message).to_bytes());
        message.zeroize();
    }
    catalog.records.extend(additions);
    catalog.records.sort_by_key(|record| {
        serde_jcs::to_vec(&record.subject).expect("provenance subject is serializable")
    });
    catalog.validate_shape()?;
    rewrite_private_json(&catalog_path, &serde_json::to_value(catalog)?)?;
    Ok(())
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
        bail!("macOS enrollment generation plan has invalid IDs or release digest");
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

#[cfg(feature = "triad-dev-harness")]
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
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
    use std::os::unix::fs::PermissionsExt as _;

    fn template_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join("packaging/triad/macos/config")
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
            login_uid: uid,
            broker_uid: uid,
            signer_uid: uid,
            session_socket_gid: rustix::process::getegid().as_raw(),
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
