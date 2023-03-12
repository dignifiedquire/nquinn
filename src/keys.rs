use std::str;

use aes::cipher::{BlockEncrypt, KeyInit};
use bytes::BytesMut;
use noise_protocol::U8Array;
use noise_protocol::{Cipher, DH};
use noise_rust_crypto::{sensitive::Sensitive, Aes256Gcm, X25519};
use quinn_proto::{
    crypto::{self, CryptoError, KeyPair, Keys},
    ConnectionId, Side,
};

use crate::session::{HandshakeState, VERSION};

/// Header protection key.
pub struct HeaderProtectionKey(aes::Aes256);

/// AES Block len
const BLOCK_LEN: usize = 16;
/// Expected sample length for the key's algorithm.
const SAMPLE_LEN: usize = BLOCK_LEN;

impl HeaderProtectionKey {
    fn from_secret(secret: &[u8]) -> Self {
        let secret = hkdf_expand(secret, b"quic hp", &[]);
        let aes = aes::Aes256::new_from_slice(secret.as_slice()).expect("known size");
        Self(aes)
    }

    /// Adds QUIC Header Protection.
    ///
    /// `sample` must contain the sample of encrypted payload; see
    /// [Header Protection Sample].
    ///
    /// `first` must reference the first byte of the header, referred to as
    /// `packet[0]` in [Header Protection Application].
    ///
    /// `packet_number` must reference the Packet Number field; this is
    /// `packet[pn_offset:pn_offset+pn_length]` in [Header Protection Application].
    ///
    /// Returns an error without modifying anything if `sample` is not
    /// the correct length (see [Header Protection Sample] and [`Self::sample_len()`]),
    /// or `packet_number` is longer than allowed (see [Packet Number Encoding and Decoding]).
    ///
    /// Otherwise, `first` and `packet_number` will have the header protection added.
    ///
    /// [Header Protection Application]: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1
    /// [Header Protection Sample]: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.2
    /// [Packet Number Encoding and Decoding]: https://datatracker.ietf.org/doc/html/rfc9000#section-17.1
    #[inline]
    pub fn encrypt_in_place(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8]) {
        self.xor_in_place(sample, first, packet_number, false)
            .unwrap();
    }

    /// Removes QUIC Header Protection.
    ///
    /// `sample` must contain the sample of encrypted payload; see
    /// [Header Protection Sample].
    ///
    /// `first` must reference the first byte of the header, referred to as
    /// `packet[0]` in [Header Protection Application].
    ///
    /// `packet_number` must reference the Packet Number field; this is
    /// `packet[pn_offset:pn_offset+pn_length]` in [Header Protection Application].
    ///
    /// Returns an error without modifying anything if `sample` is not
    /// the correct length (see [Header Protection Sample] and [`Self::sample_len()`]),
    /// or `packet_number` is longer than allowed (see
    /// [Packet Number Encoding and Decoding]).
    ///
    /// Otherwise, `first` and `packet_number` will have the header protection removed.
    ///
    /// [Header Protection Application]: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1
    /// [Header Protection Sample]: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.2
    /// [Packet Number Encoding and Decoding]: https://datatracker.ietf.org/doc/html/rfc9000#section-17.1
    #[inline]
    pub fn decrypt_in_place(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8]) {
        self.xor_in_place(sample, first, packet_number, true)
            .unwrap();
    }

    /// Encrypts the sample as a single block.
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], &'static str> {
        let sample: [u8; SAMPLE_LEN] = sample.try_into().map_err(|_| "invalid sample size")?;
        let mut block = sample.into();
        self.0.encrypt_block(&mut block);
        let mut out = [0u8; 5];
        out.copy_from_slice(&block[..5]);
        Ok(out)
    }

    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), &'static str> {
        // This implements [Header Protection Application] almost verbatim.

        let mask = self.new_mask(sample)?;

        // The `unwrap()` will not panic because `new_mask` returns a
        // non-empty result.
        let (first_mask, pn_mask) = mask.split_first().unwrap();

        // It is OK for the `mask` to be longer than `packet_number`,
        // but a valid `packet_number` will never be longer than `mask`.
        if packet_number.len() > pn_mask.len() {
            return Err("packet number too long");
        }

        // Infallible from this point on. Before this point, `first` and
        // `packet_number` are unchanged.

        const LONG_HEADER_FORM: u8 = 0x80;
        let bits = match *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            true => 0x0f,  // Long header: 4 bits masked
            false => 0x1f, // Short header: 5 bits masked
        };

        let first_plain = match masked {
            // When unmasking, use the packet length bits after unmasking
            true => *first ^ (first_mask & bits),
            // When masking, use the packet length bits before masking
            false => *first,
        };
        let pn_len = (first_plain & 0x03) as usize + 1;

        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= m;
        }

        Ok(())
    }
}

impl crypto::HeaderKey for HeaderProtectionKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.decrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        );
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.encrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        );
    }

    fn sample_size(&self) -> usize {
        SAMPLE_LEN
    }
}

pub struct PacketKey {
    key: <noise_rust_crypto::Aes256Gcm as Cipher>::Key,
}

impl PacketKey {
    fn from_secret(secret: &[u8]) -> Self {
        let key = hkdf_expand(secret, b"quic key", &[]);
        PacketKey { key }
    }
}

/// AES GCM 256 tag size
const TAG_LEN: usize = 16;
const MAXMSG_LEN: usize = 65_535;

impl crypto::PacketKey for PacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload) = buf.split_at_mut(header_len);
        assert!(payload.len() <= MAXMSG_LEN);

        let payload_in = payload[..payload.len() - TAG_LEN].to_vec(); // TODO: avoid

        Aes256Gcm::encrypt(&self.key, packet, &header, &payload_in, payload);
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plain_len = payload
            .len()
            .checked_sub(self.tag_len())
            .ok_or_else(|| CryptoError)?;
        let payload_in = payload.to_vec(); // TODO: avoid
        let payload_out = &mut payload[..plain_len];
        Aes256Gcm::decrypt(&self.key, packet, header, &payload_in, payload_out)
            .map_err(|_| CryptoError)?;

        payload.truncate(plain_len);

        Ok(())
    }

    fn tag_len(&self) -> usize {
        Aes256Gcm::tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        // TODO: verify, based on the values in rustls
        1 << 23
    }

    fn integrity_limit(&self) -> u64 {
        // TODO: verify, based on the values in rustls
        1 << 52
    }
}

/// Constructs initial packet protection keys.
///
/// The algorithm follows Quic TLS RFC 9001 Section 5.1.
/// To reduce the amount of different algorihtms used this uses AES GCM 256 and not 128 as the TLS spec.
pub(crate) fn initial_keys(version: u32, dst_cid: &ConnectionId, side: Side) -> Keys {
    debug_assert_eq!(version, VERSION);

    const CLIENT_LABEL: &[u8] = b"client in";
    const SERVER_LABEL: &[u8] = b"server in";

    // Version1 from https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets// https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets
    const INITIAL_SALT: &[u8] = &[
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];

    let (hs_secret, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(INITIAL_SALT), dst_cid);
    let client_secret = hkdf_expand(&hs_secret, CLIENT_LABEL, &[]);
    let server_secret = hkdf_expand(&hs_secret, SERVER_LABEL, &[]);

    new_keys(&Secret {
        client: client_secret,
        server: server_secret,
        side,
    })
}

fn new_keys(secret: &Secret) -> Keys {
    let (local, remote) = secret.local_remote();
    let (header_local, header_remote) = (
        HeaderProtectionKey::from_secret(local),
        HeaderProtectionKey::from_secret(remote),
    );

    let packet = new_packet_keys(secret);
    Keys {
        header: KeyPair {
            local: Box::new(header_local),
            remote: Box::new(header_remote),
        },
        packet,
    }
}

fn new_packet_keys(secret: &Secret) -> KeyPair<Box<dyn crypto::PacketKey>> {
    let (local, remote) = secret.local_remote();
    let (packet_local, packet_remote) = (
        PacketKey::from_secret(local),
        PacketKey::from_secret(remote),
    );
    KeyPair {
        local: Box::new(packet_local),
        remote: Box::new(packet_remote),
    }
}

pub struct Secret {
    client: Sensitive<[u8; 32]>,
    server: Sensitive<[u8; 32]>,
    side: Side,
}

impl Secret {
    fn local_remote(&self) -> (&[u8; 32], &[u8; 32]) {
        match self.side {
            Side::Client => (&self.client, &self.server),
            Side::Server => (&self.server, &self.client),
        }
    }

    pub fn next_packet_keys(&mut self) -> KeyPair<Box<dyn crypto::PacketKey>> {
        let keys = new_packet_keys(&self);
        self.update();
        keys
    }

    fn update(&mut self) {
        // This is the expansion from TLS
        // TODO: this should probably be switched to the rekey
        // method from noise.
        self.client = hkdf_expand(self.client.as_slice(), b"quic ku", &[]);
        self.server = hkdf_expand(self.server.as_slice(), b"quic ku", &[]);
    }
}

fn hkdf_expand(prk: &[u8], label: &[u8], context: &[u8]) -> Sensitive<[u8; 32]> {
    const LABEL_PREFIX: &[u8] = b"quic-noise ";

    let label_len = u8::try_from(LABEL_PREFIX.len() + label.len())
        .expect("label too large")
        .to_be_bytes();
    let context_len = u8::try_from(context.len())
        .expect("context too large")
        .to_be_bytes();

    let hs = hkdf::Hkdf::<sha2::Sha256>::from_prk(prk).expect("invalid prk");
    let info = [
        &label_len[..],
        LABEL_PREFIX,
        label,
        &context_len[..],
        context,
    ];

    let mut out = Sensitive::<[u8; 32]>::from_slice(&[0u8; 32]);
    hs.expand_multi_info(&info, out.as_mut())
        .expect("invalid expansion length");

    out
}

pub fn keys_from_handshake_state(hs: &HandshakeState, side: Side) -> (Keys, Secret) {
    // Can not use `StatelessTransportMode` directly, so split manually.
    let (left_secret, right_secret) = hs.get_ciphers();

    let mut secrets = Secret {
        client: left_secret.extract().0,
        server: right_secret.extract().0,
        side,
    };
    let keys = new_keys(&secrets);
    secrets.update();
    (keys, secrets)
}

pub type DhPublicKey = <X25519 as DH>::Pubkey;
pub type DhPrivateKey = <X25519 as DH>::Key;

pub struct DhKeypair {
    pub private: DhPrivateKey,
    pub public: DhPublicKey,
}

impl DhKeypair {
    pub fn private(&self) -> DhPrivateKey {
        U8Array::clone(&self.private)
    }

    pub fn public(&self) -> DhPublicKey {
        U8Array::clone(&self.public)
    }
}

impl Default for DhKeypair {
    fn default() -> Self {
        let private = X25519::genkey();
        let public = X25519::pubkey(&private);
        DhKeypair { private, public }
    }
}
