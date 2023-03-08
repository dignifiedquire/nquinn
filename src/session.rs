use std::{any::Any, str, sync::Arc};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::{AeadInPlace, NewAead};
use bytes::BytesMut;
use snow::resolvers::CryptoResolver;

use quinn_proto::{
    crypto::{
        self, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, UnsupportedVersion,
    },
    transport_parameters::TransportParameters,
    ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
};

/// Version number based on the original version suggested by the nQuic paper.
const VERSION: u32 = 0xff00000b;

const PATTERN: &str = "Noise_IK_25519_AESGCM_SHA256";
const STATIC_DUMMY_SECRET: [u8; 32] = [
    0xe0, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// A nquic session
pub struct NquicSession {
    /// Noise handshake data.
    handshake: Option<snow::HandshakeState>,
    /// Authenticated remote handshake data.
    handshake_data_remote: Option<HandshakeData>,
    /// Local transport parameters
    params_local: TransportParameters,
    /// Available ALPN protocol names.
    /// Ordered by most perferred first.
    alpn_protocols: Vec<Vec<u8>>,
    side: Side,
    handshake_sent: bool,
}

impl crypto::Session for NquicSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_keys(VERSION, dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.handshake_data_remote
            .as_ref()
            .map(|h| -> Box<dyn Any> { Box::new(h.clone()) })
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        // TODO: what should this be?
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn crypto::PacketKey>)> {
        todo!()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        todo!()
    }

    fn is_handshaking(&self) -> bool {
        self.handshake.is_some()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        if let Some(ref mut hs) = self.handshake {
            if self.handshake_data_remote.is_some() {
                return Err(protocol_violation("remote handshake data already received"));
            }

            let buf_len = buf.len().min(65_535);
            let mut read_buf = vec![0u8; buf_len];

            match hs.read_message(buf, &mut read_buf) {
                Ok(n) => {
                    let payload = &read_buf[..n];
                    let remote_side = !self.side;
                    let handshake_data = HandshakeData::from_bytes(payload, remote_side)
                        .map_err(protocol_violation)?;

                    match self.side {
                        Side::Client => {
                            assert!(hs.is_initiator());
                            assert!(hs.is_handshake_finished());

                            match handshake_data {
                                HandshakeData::Client { .. } => {
                                    return Err(protocol_violation(format!(
                                        "handshake: expected server response, got client response"
                                    )));
                                }
                                HandshakeData::Server {
                                    ref alpn_protocol, ..
                                } => {
                                    // Validate ALPN choice
                                    if let Some(alpn_protocol) = alpn_protocol {
                                        if !self.alpn_protocols.contains(alpn_protocol) {
                                            return Err(protocol_violation(format!(
                                                "handshake: invalid ALPN selected"
                                            )));
                                        }
                                    }
                                }
                            }
                        }
                        Side::Server => {
                            assert!(!hs.is_initiator());

                            match handshake_data {
                                HandshakeData::Client { .. } => {
                                    // TODO: validate client identity?
                                }
                                HandshakeData::Server { .. } => {
                                    return Err(protocol_violation(format!(
                                        "handshake: expected client response, got server response"
                                    )));
                                }
                            }
                        }
                    }
                    self.handshake_data_remote = Some(handshake_data);

                    Ok(true)
                }
                Err(e) => Err(protocol_violation(format!("Noise error: {e}"))),
            }
        } else {
            Err(protocol_violation(format!("unexpected handshake")))
        }
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        Ok(self
            .handshake_data_remote
            .as_ref()
            .map(|h| h.transport_parameters().clone()))
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        if let Some(ref mut hs) = self.handshake {
            match self.side {
                Side::Client => {
                    if !self.handshake_sent {
                        // Send handshake request
                        let response = HandshakeData::Client {
                            alpn_protocols: self.alpn_protocols.clone(),
                            transport_parameters: self.params_local.clone(),
                        };

                        let payload = response.as_bytes();
                        let len = hs.write_message(&payload, buf).unwrap();
                        self.handshake_sent = true;

                        None
                    } else {
                        // Handshake finished.
                        assert!(self.handshake_data_remote.is_some());
                        assert!(hs.is_handshake_finished());

                        drop(hs);
                        let mut hs = self.handshake.take().unwrap();

                        // Can not use `StatelessTransportMode` directly, so split manually.

                        let keys = keys_from_handshake_state(hs);
                        Some(keys)
                    }
                }
                Side::Server => {
                    assert!(!hs.is_initiator());
                    if !self.handshake_sent {
                        // On the server side nothing todo in the first round.
                        self.handshake_sent = true;
                        None
                    } else {
                        // Send handshake response.
                        assert!(self.handshake_data_remote.is_some());
                        // respond
                        let handshake_data_remote = self.handshake_data_remote.as_ref().unwrap();
                        let response = HandshakeData::Server {
                            alpn_protocol: handshake_data_remote
                                .select_alpn_protocol(&self.alpn_protocols),
                            server_name: None, // TODO:
                            transport_parameters: self.params_local.clone(),
                        };

                        let payload = response.as_bytes();
                        let len = hs.write_message(&payload, buf).unwrap();
                        assert!(hs.is_handshake_finished());

                        drop(hs);
                        let hs = self.handshake.take().unwrap();
                        let keys = keys_from_handshake_state(hs);
                        Some(keys)
                    }
                }
            }
        } else {
            panic!("unexpected write_handshake during transport");
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        todo!()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        todo!()
    }
}

const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

fn is_valid_retry(orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
    let tag_start = match payload.len().checked_sub(16) {
        Some(x) => x,
        None => return false,
    };

    let mut pseudo_packet =
        Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
    pseudo_packet.push(orig_dst_cid.len() as u8);
    pseudo_packet.extend_from_slice(orig_dst_cid);
    pseudo_packet.extend_from_slice(header);
    let tag_start = tag_start + pseudo_packet.len();
    pseudo_packet.extend_from_slice(payload);

    let (nonce, key) = (RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1);

    let key = aes_gcm::Aes128Gcm::new_from_slice(&key[..]).unwrap();
    let mut tag = pseudo_packet.split_off(tag_start);
    let aad = pseudo_packet;
    key.decrypt_in_place(&nonce.into(), &aad, &mut tag).is_ok()
}

pub struct HeaderProtectionKey(aes::Aes256);

/// AES Block len
const BLOCK_LEN: usize = 16;
/// Expected sample length for the key's algorithm.
const SAMPLE_LEN: usize = BLOCK_LEN;

impl HeaderProtectionKey {
    fn from_secret(secret: &[u8]) -> Self {
        let secret = hkdf_expand(secret, b"quic hp", &[]);
        let aes = aes::Aes256::new_from_slice(&secret).expect("known size");
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

/// Authentication data for a snow session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeData {
    /// The data sent by the client -> server
    Client {
        /// List of available protocols.
        alpn_protocols: Vec<Vec<u8>>,
        /// Client transport parameters.
        transport_parameters: TransportParameters,
    },
    /// The data sent by server -> client as repsonse.
    Server {
        /// Selected protocol.
        alpn_protocol: Option<Vec<u8>>,
        /// The server name specified by the client, if any
        server_name: Option<String>,
        /// Server transport parameters.
        transport_parameters: TransportParameters,
    },
}

impl HandshakeData {
    fn side(&self) -> Side {
        match self {
            HandshakeData::Client { .. } => Side::Client,
            HandshakeData::Server { .. } => Side::Server,
        }
    }
    fn from_bytes(bytes: &[u8], side: Side) -> Result<Self, &'static str> {
        fn read<I: std::slice::SliceIndex<[u8]>>(
            bytes: &[u8],
            pos: I,
        ) -> Result<&I::Output, &'static str> {
            bytes.get(pos).ok_or_else(|| "unexpected eof")
        }
        let mut pos = 0;

        // Side
        let side_byte = *read(bytes, pos)?;
        match (side_byte, side) {
            (0, Side::Client) | (1, Side::Server) => {
                // all good
            }
            (_, _) => {
                return Err("side missmatch");
            }
        }
        pos += 1;

        // Protocols
        let num_alpn_protocols = *read(bytes, pos)? as usize;
        pos += 1;

        if side == Side::Server && num_alpn_protocols > 1 {
            return Err("too many ALPN protocols");
        }

        let mut alpn_protocols = Vec::with_capacity(num_alpn_protocols);
        for _ in 0..num_alpn_protocols {
            let len = *read(bytes, pos)? as usize;
            pos += 1;
            let protocol = read(bytes, pos..pos + len)?.to_vec();
            alpn_protocols.push(protocol);
            pos += len;
        }

        match side {
            Side::Client => {
                // transport params
                let transport_parameters =
                    TransportParameters::read(side, &mut std::io::Cursor::new(&bytes[pos..]))
                        .map_err(|_| "invalid transport parameters")?;

                Ok(HandshakeData::Client {
                    alpn_protocols,
                    transport_parameters,
                })
            }
            Side::Server => {
                let server_name_len = *read(bytes, pos)? as usize;
                pos += 1;
                let server_name = if server_name_len == 0 {
                    None
                } else {
                    let name_raw = read(bytes, pos..pos + server_name_len)?;
                    pos += server_name_len;
                    let name_str =
                        std::str::from_utf8(name_raw).map_err(|_| "invalid servername")?;
                    Some(name_str.to_string())
                };

                // transport params
                let transport_parameters =
                    TransportParameters::read(side, &mut std::io::Cursor::new(&bytes[pos..]))
                        .map_err(|_| "invalid transport parameters")?;

                Ok(HandshakeData::Server {
                    alpn_protocol: alpn_protocols.pop(),
                    server_name,
                    transport_parameters,
                })
            }
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        match self {
            HandshakeData::Client {
                ref alpn_protocols,
                ref transport_parameters,
            } => {
                // Side
                out.push(0);

                // ALPN
                out.push(u8::try_from(alpn_protocols.len()).expect("too many protocols"));
                for protocol in alpn_protocols {
                    // length prefix
                    out.push(u8::try_from(protocol.len()).expect("protocol name too large"));
                    out.extend_from_slice(protocol);
                }

                // transport parameters
                transport_parameters.write(&mut out);
            }
            HandshakeData::Server {
                ref alpn_protocol,
                ref server_name,
                ref transport_parameters,
            } => {
                // Side
                out.push(1);

                // ALPN
                match alpn_protocol {
                    None => {
                        out.push(0);
                    }
                    Some(protocol) => {
                        out.push(1);
                        // length prefix
                        out.push(u8::try_from(protocol.len()).expect("protocol name too large"));
                        out.extend_from_slice(protocol);
                    }
                }

                // Server Name
                match server_name {
                    None => {
                        out.push(0);
                    }
                    Some(name) => {
                        // length prefix
                        out.push(u8::try_from(name.len()).expect("server name too large"));
                        out.extend_from_slice(name.as_bytes());
                    }
                }

                // transport parameters
                transport_parameters.write(&mut out);
            }
        }

        out
    }

    fn transport_parameters(&self) -> &TransportParameters {
        match self {
            HandshakeData::Client {
                ref transport_parameters,
                ..
            } => transport_parameters,
            HandshakeData::Server {
                ref transport_parameters,
                ..
            } => transport_parameters,
        }
    }

    /// Selects the first matching protocol and returns it. Returns `None` if no match is found.
    fn select_alpn_protocol(&self, other_protocols: &[Vec<u8>]) -> Option<Vec<u8>> {
        let self_protocols = match self {
            HandshakeData::Client {
                ref alpn_protocols, ..
            } => alpn_protocols,
            HandshakeData::Server { .. } => {
                return None;
            }
        };

        // TODO: which side should have preference?
        for protocol in self_protocols.iter() {
            if other_protocols.contains(protocol) {
                return Some(protocol.clone());
            }
        }

        None
    }
}

pub struct ClientConfig {
    pub remote_public_key: [u8; 32],
    pub local_private_key: [u8; 32],
    /// Available ALPN protocol names.
    /// Ordered by most perferred first.
    pub alpn_protocols: Vec<Vec<u8>>,
}

impl crypto::ClientConfig for ClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        debug_assert_eq!(version, VERSION);

        // TODO: include server_name in the prologue?

        let handshake = snow::Builder::new(PATTERN.parse().unwrap())
            .local_private_key(&self.local_private_key)
            .remote_public_key(&self.remote_public_key)
            .build_initiator()
            .unwrap();
        Ok(Box::new(NquicSession {
            handshake: Some(handshake),
            handshake_data_remote: None,
            params_local: params.clone(),
            alpn_protocols: self.alpn_protocols.clone(),
            side: Side::Client,
            handshake_sent: false,
        }))
    }
}

pub struct ServerConfig {
    /// Available ALPN protocol names.
    /// Ordered by most perferred first.
    pub alpn_protocols: Vec<Vec<u8>>,
    pub local_private_key: [u8; 32],
}

impl crypto::ServerConfig for ServerConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        debug_assert_eq!(version, VERSION);

        let handshake = snow::Builder::new(PATTERN.parse().unwrap())
            .local_private_key(&self.local_private_key)
            .build_responder()
            .unwrap();
        Box::new(NquicSession {
            handshake: Some(handshake),
            handshake_data_remote: None,
            params_local: params.clone(),
            alpn_protocols: self.alpn_protocols.clone(),
            side: Side::Server,
            handshake_sent: false,
        })
    }

    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<Keys, UnsupportedVersion> {
        if version != VERSION {
            return Err(UnsupportedVersion);
        }
        Ok(initial_keys(version, dst_cid, side))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        debug_assert_eq!(version, VERSION);
        let (nonce, key) = (RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1);

        let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(packet);

        let key = aes_gcm::Aes128Gcm::new_from_slice(&key[..]).unwrap();

        let tag = key
            .encrypt_in_place_detached(&nonce.into(), &pseudo_packet, &mut Vec::new())
            .unwrap();
        let mut result = [0; 16];
        result.copy_from_slice(tag.as_ref());
        result
    }
}

#[derive(Default)]
pub struct PacketKey {
    cipher: Option<Box<dyn snow::types::Cipher>>,
}

impl PacketKey {
    fn from_secret(secret: &[u8]) -> Self {
        let resolver = snow::resolvers::DefaultResolver::default();
        let mut cipher = resolver
            .resolve_cipher(&snow::params::CipherChoice::AESGCM)
            .unwrap();
        cipher.set(secret);
        PacketKey {
            cipher: Some(cipher),
        }
    }
}

/// AES GCM 256 tag size
const TAG_LEN: usize = 16;
const MAXMSG_LEN: usize = 65_535;

impl crypto::PacketKey for PacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let cipher = self.cipher.as_ref().expect("handshake not completed");
        let (header, payload) = buf.split_at_mut(header_len);

        assert!(header.len() + TAG_LEN <= MAXMSG_LEN && header.len() + TAG_LEN <= payload.len());

        cipher.encrypt(packet, &[], &*header, payload);
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let cipher = self.cipher.as_ref().expect("handshake not completed");
        let plain_len = cipher
            .decrypt(packet, &[], header, payload.as_mut())
            .map_err(|_| CryptoError)?;
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
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

    let (local_secret, remote_secret) = match side {
        Side::Client => (&client_secret, &server_secret),
        Side::Server => (&server_secret, &client_secret),
    };

    let (header_local, header_remote) = (
        HeaderProtectionKey::from_secret(local_secret),
        HeaderProtectionKey::from_secret(remote_secret),
    );

    let (packet_local, packet_remote) = (PacketKey::default(), PacketKey::default());

    Keys {
        header: KeyPair {
            local: Box::new(header_local),
            remote: Box::new(header_remote),
        },
        packet: KeyPair {
            local: Box::new(packet_local),
            remote: Box::new(packet_remote),
        },
    }
}

/// Output size for sha2::Sha256.
const OKM_SIZE: usize = 32;

fn hkdf_expand(prk: &[u8], label: &[u8], context: &[u8]) -> [u8; OKM_SIZE] {
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

    let mut out = [0u8; OKM_SIZE];
    hs.expand_multi_info(&info, &mut out)
        .expect("invalid expansion length");

    out
}

fn keys_from_handshake_state(mut hs: snow::HandshakeState) -> Keys {
    let (local_secret, remote_secret) = hs.dangerously_get_raw_split();

    let header_local = HeaderProtectionKey::from_secret(&local_secret);
    let header_remote = HeaderProtectionKey::from_secret(&remote_secret);

    let packet_local = PacketKey::from_secret(&local_secret);
    let packet_remote = PacketKey::from_secret(&remote_secret);

    Keys {
        header: KeyPair {
            local: Box::new(header_local),
            remote: Box::new(header_remote),
        },
        packet: KeyPair {
            local: Box::new(packet_local),
            remote: Box::new(packet_remote),
        },
    }
}

fn protocol_violation(reason: impl Into<String>) -> TransportError {
    TransportError {
        code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame: None,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use quinn_proto::crypto::ServerConfig as _;
    use rand::RngCore;

    fn check_roundtrip(hs: HandshakeData) {
        let bytes = hs.as_bytes();
        let back = HandshakeData::from_bytes(&bytes, hs.side()).unwrap();
        assert_eq!(hs, back);
    }

    #[test]
    fn test_handshake_data_roundtrip() {
        check_roundtrip(HandshakeData::Client {
            alpn_protocols: vec![],
            transport_parameters: TransportParameters::default(),
        });

        check_roundtrip(HandshakeData::Client {
            alpn_protocols: vec![b"hello".to_vec(), b"world".to_vec()],
            transport_parameters: TransportParameters::default(),
        });

        check_roundtrip(HandshakeData::Server {
            alpn_protocol: None,
            server_name: None,
            transport_parameters: TransportParameters::default(),
        });

        check_roundtrip(HandshakeData::Server {
            alpn_protocol: None,
            server_name: Some("hello".to_string()),
            transport_parameters: TransportParameters::default(),
        });

        check_roundtrip(HandshakeData::Server {
            alpn_protocol: Some(b"hello".to_vec()),
            server_name: Some("hello".to_string()),
            transport_parameters: TransportParameters::default(),
        });
    }

    #[test]
    fn test_retry_tag() {
        let mut local_private_key = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut local_private_key);

        let server_config = ServerConfig {
            alpn_protocols: vec![b"hello".to_vec()],
            local_private_key,
        };

        let dest_cid = ConnectionId::new(&[1, 2, 3]);
        let mut packet = [0u8; 128];
        rng.fill_bytes(&mut packet);

        let retry_tag = server_config.retry_tag(VERSION, &dest_cid, &packet);

        // TODO: figure out how to test this
        // assert!(is_valid_retry(&dest_cid, &packet[..16] retry_tag))
    }
}
