use std::{fs, io::Write, path::Path};

use anyhow::{Context, Result, bail};
use iroh::SecretKey;

/// Dedicated Iroh identity. It is never a Bloom wallet or signer key.
#[derive(Clone, Debug)]
pub struct PeerIdentity {
    secret: SecretKey,
}

impl PeerIdentity {
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::generate(),
        }
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let bytes =
                fs::read(path).with_context(|| format!("read peer identity {}", path.display()))?;
            if bytes.len() != 32 {
                bail!("peer identity must contain exactly 32 bytes");
            }
            let mut key = [0_u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(Self {
                secret: SecretKey::from_bytes(&key),
            });
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create peer identity dir {}", parent.display()))?;
        }
        let identity = Self::generate();
        let tmp = path.with_extension("tmp");
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("create peer identity {}", tmp.display()))?;
        file.write_all(&identity.secret.to_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp, path)
            .with_context(|| format!("install peer identity {}", path.display()))?;
        Ok(identity)
    }

    pub fn endpoint_id(&self) -> iroh::EndpointId {
        self.secret.public()
    }

    pub(crate) fn secret_key(&self) -> &SecretKey {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let first = PeerIdentity::load_or_create(&path).unwrap();
        let second = PeerIdentity::load_or_create(&path).unwrap();
        assert_eq!(first.endpoint_id(), second.endpoint_id());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
