//! Implementation of the cryptographic primitives needed in quinn
//! using rustcrypto.

use aes::cipher::{generic_array::GenericArray, KeySizeUser, Unsigned};
use aes_gcm::aead::{AeadCore, AeadInPlace, NewAead};
use hkdf::hmac::{self, Mac};
use quinn_proto::crypto::{self, CryptoError};
use rand::RngCore;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

pub struct HmacKey(GenericArray<u8, <HmacSha256 as KeySizeUser>::KeySize>);

impl Default for HmacKey {
    fn default() -> Self {
        let rng = &mut rand::thread_rng();
        let mut key = [0u8; 64];
        rng.fill_bytes(&mut key);
        HmacKey(key.into())
    }
}

impl crypto::HmacKey for HmacKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        let mut h = <HmacSha256 as Mac>::new(&self.0);
        h.update(data);
        let res = h.finalize().into_bytes();
        signature_out.copy_from_slice(&res);
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let mut h = <HmacSha256 as Mac>::new(&self.0);
        h.update(data);
        h.verify_slice(signature).map_err(|_| CryptoError)?;
        Ok(())
    }
}

pub struct HandshakeTokenKey(hkdf::Hkdf<sha2::Sha256>);

impl Default for HandshakeTokenKey {
    fn default() -> Self {
        let rng = &mut rand::thread_rng();
        let mut master_key = [0u8; 64];
        rng.fill_bytes(&mut master_key);
        let master_key = hkdf::Hkdf::new(None, &master_key);
        HandshakeTokenKey(master_key)
    }
}

impl crypto::HandshakeTokenKey for HandshakeTokenKey {
    /// Derive AEAD using hkdf
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn crypto::AeadKey> {
        let mut key_buffer = [0u8; 32];
        self.0.expand(random_bytes, &mut key_buffer).unwrap();
        let key: aes_gcm::Key<<aes_gcm::Aes256Gcm as NewAead>::KeySize> = key_buffer.into();
        Box::new(AeadKey(aes_gcm::Aes256Gcm::new(&key)))
    }
}

pub struct AeadKey(aes_gcm::Aes256Gcm);

/// A key for sealing data with AEAD-based algorithms
impl crypto::AeadKey for AeadKey {
    /// Method for sealing message `data`
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError> {
        let zero_nonce = aes_gcm::Nonce::default();
        self.0
            .encrypt_in_place(&zero_nonce, additional_data, data)
            .map_err(|_| CryptoError)?;
        Ok(())
    }

    /// Method for opening a sealed message `data`
    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        let zero_nonce = aes_gcm::Nonce::default();
        let tag_size = <aes_gcm::Aes256Gcm as AeadCore>::TagSize::to_usize();
        if data.len() < tag_size {
            return Err(CryptoError);
        }

        let tag_pos = data.len() - tag_size;
        let (msg, tag) = data.as_mut().split_at_mut(tag_pos);
        self.0
            .decrypt_in_place_detached(
                &zero_nonce,
                additional_data,
                msg,
                aes_gcm::Tag::from_slice(tag),
            )
            .map_err(|_| CryptoError)?;

        Ok(&mut data[..tag_pos])
    }
}

#[cfg(test)]
mod tests {
    use quinn::crypto::{HandshakeTokenKey as _, HmacKey as _};

    use super::*;

    #[test]
    fn test_hmac_key() {
        let mut rng = rand::thread_rng();

        let key = HmacKey::default();
        let mut data = [0u8; 128];
        rng.fill_bytes(&mut data);

        let mut signature = vec![0u8; key.signature_len() as usize];
        key.sign(&data, &mut signature);
        assert!(key.verify(&data, &signature).is_ok());
    }

    #[test]
    fn test_handshake_token_key() {
        let mut rng = rand::thread_rng();

        let key = HandshakeTokenKey::default();
        let mut random_bytes = [0u8; 32];
        rng.fill_bytes(&mut random_bytes);

        let aead_key = key.aead_from_hkdf(&random_bytes);

        let mut data = vec![0u8; 128];
        rng.fill_bytes(&mut data);
        let mut add = [0u8; 16];
        rng.fill_bytes(&mut add);

        let mut sealed = data.clone();
        aead_key.seal(&mut sealed, &add).unwrap();
        let unsealed = aead_key.open(&mut sealed, &add).unwrap();

        assert_eq!(data, unsealed);
    }
}
