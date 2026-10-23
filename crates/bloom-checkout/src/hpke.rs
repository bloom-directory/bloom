use anyhow::{Result, bail};
use bloom_signer_api::{Base64UrlBytes, HpkeEnvelope};
use hpke::{
    Deserializable, Kem as _, OpModeR, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};
use zeroize::Zeroizing;

/// One approval has one recipient. Consuming it prevents local decryption retry.
pub(crate) struct Recipient {
    secret: Zeroizing<Vec<u8>>,
    pub public: Base64UrlBytes,
}
impl Recipient {
    pub fn generate() -> Self {
        let (secret, public) = X25519HkdfSha256::gen_keypair();
        Self {
            secret: Zeroizing::new(secret.to_bytes().to_vec()),
            public: Base64UrlBytes::from_bytes(&public.to_bytes()),
        }
    }
    pub fn open(self, envelope: &HpkeEnvelope, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if envelope.ciphertext.decode().len() > 4096 {
            bail!("Card release exceeds limit");
        }
        envelope
            .validate()
            .map_err(|_| anyhow::anyhow!("Invalid card envelope"))?;
        let secret = <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&self.secret)
            .map_err(|_| anyhow::anyhow!("Invalid recipient key"))?;
        let encapsulated =
            <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&envelope.kem_output.decode())
                .map_err(|_| anyhow::anyhow!("Invalid release encapsulation"))?;
        let mut receiver = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &secret,
            &encapsulated,
            b"bloom-custody-output/v1",
        )
        .map_err(|_| anyhow::anyhow!("Card release authentication failed"))?;
        let plaintext = receiver
            .open(&envelope.ciphertext.decode(), aad)
            .map_err(|_| anyhow::anyhow!("Card release authentication failed"))?;
        Ok(Zeroizing::new(plaintext))
    }
}
