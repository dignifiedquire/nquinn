use std::fmt::Debug;
use std::{any::Any, str, sync::Arc};

use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::{AeadInPlace, NewAead};
use bytes::BytesMut;
use noise_protocol::U8Array;
use noise_protocol::{Cipher, HandshakeStateBuilder, DH};
use noise_rust_crypto::{sensitive::Sensitive, Aes256Gcm, Sha256, X25519};
use quinn_proto::{
    crypto::{
        self, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, UnsupportedVersion,
    },
    transport_parameters::TransportParameters,
    ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
};

/// Version number based on the original version suggested by the nQuic paper.
pub const VERSION: u32 = 0xff00000b;

const PATTERN: &str = "Noise_IK_25519_AESGCM_SHA256";
const STATIC_DUMMY_SECRET: [u8; 32] = [
    0xe0, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

type HandshakeState = noise_protocol::HandshakeState<X25519, Aes256Gcm, Sha256>;

/// A nquic session
pub struct NquicSession {
    /// Authenticated remote handshake data.
    handshake_data_remote: Option<HandshakeData>,
    /// Local transport parameters
    params_local: TransportParameters,
    /// Available ALPN protocol names.
    /// Ordered by most perferred first.
    alpn_protocols: Vec<Vec<u8>>,
    side: Side,
    state: State,
    /// Set of next sedcrets to use.
    next_secrets: Option<Secret>,
}

enum State {
    Initial(HandshakeState),
    ZeroRtt(HandshakeState),
    Handshake(HandshakeState),
    OneRtt(HandshakeState),
    Data,
    /// Represents the state of an invalid state transition during panics.
    Invalid,
}

impl State {
    fn get_handshake_state(&self) -> Option<&HandshakeState> {
        match &self {
            State::Initial(hs) | State::ZeroRtt(hs) | State::Handshake(hs) | State::OneRtt(hs) => {
                Some(hs)
            }
            State::Data => None,
            State::Invalid => panic!("state poisend"),
        }
    }

    fn to_one_rtt(&mut self) {
        match std::mem::replace(self, State::Invalid) {
            State::Handshake(hs) => {
                *self = State::OneRtt(hs);
            }
            _ => panic!("invalid state transition"),
        };
    }

    fn to_zero_rtt(&mut self) {
        match std::mem::replace(self, State::Invalid) {
            State::Initial(hs) => {
                *self = State::ZeroRtt(hs);
            }
            _ => panic!("invalid state transition"),
        };
    }

    fn to_handshake(&mut self) {
        match std::mem::replace(self, State::Invalid) {
            State::ZeroRtt(hs) => {
                *self = State::Handshake(hs);
            }
            _ => panic!("invalid state transition"),
        };
    }

    fn to_data(&mut self) -> HandshakeState {
        match std::mem::replace(self, State::Invalid) {
            State::Handshake(hs) | State::OneRtt(hs) => {
                *self = State::Data;
                hs
            }
            _ => panic!("invalid state transition"),
        }
    }
}

impl Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            State::Initial(_) => "Initial",
            State::ZeroRtt(_) => "ZeroRtt",
            State::Handshake(_) => "Handshake",
            State::OneRtt(_) => "OneRtt",
            State::Data => "Data",
            State::Invalid => "Invalid",
        };
        write!(f, "State::{}", name)
    }
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
        if let Some(hs) = self.state.get_handshake_state() {
            let (keys, _) = keys_from_handshake_state(hs, self.side);
            return Some((keys.header.local, keys.packet.local));
        }

        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        // TODO: verify this
        Some(true)
    }

    fn is_handshaking(&self) -> bool {
        !matches!(self.state, State::Data)
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        println!(
            "[{:?}] read_handshake {}bytes {:?}",
            self.side,
            buf.len(),
            self.state
        );
        match (self.side, &mut self.state) {
            (Side::Server, State::Initial(ref mut hs)) => {
                let payload = hs
                    .read_message_vec(buf)
                    .map_err(|e| protocol_violation(format!("Noise error: {e}")))?;

                let handshake_data = HandshakeData::from_bytes(&payload, Side::Client)
                    .map_err(protocol_violation)?;
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
                self.handshake_data_remote = Some(handshake_data);
                self.state.to_zero_rtt();
                println!("[{:?}] got handshake data remote", self.side);

                Ok(true)
            }
            (Side::Client, State::Handshake(ref mut hs)) => {
                let payload = hs
                    .read_message_vec(buf)
                    .map_err(|e| protocol_violation(format!("Noise error: {e}")))?;

                let handshake_data = HandshakeData::from_bytes(&payload, Side::Server)
                    .map_err(protocol_violation)?;
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

                self.handshake_data_remote = Some(handshake_data);
                self.state.to_one_rtt();
                println!("[{:?}] got handshake data remote", self.side);
                Ok(true)
            }
            _ => Err(protocol_violation(format!("unexpected handshake"))),
        }
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        // TODO: verify this is the right check
        if matches!(self.state, State::Handshake(_)) && self.side == Side::Client {
            return Ok(Some(self.params_local));
        }

        Ok(self
            .handshake_data_remote
            .as_ref()
            .map(|h| *h.transport_parameters()))
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        println!(
            "[{:?}] write_handshake {:?} {}",
            self.side,
            self.state,
            self.handshake_data_remote.is_some(),
        );
        match (self.side, &mut self.state) {
            (Side::Client, State::Initial(ref mut hs)) => {
                // Send handshake request
                let response = HandshakeData::Client {
                    alpn_protocols: self.alpn_protocols.clone(),
                    transport_parameters: self.params_local.clone(),
                };
                let payload = response.as_bytes();
                buf.resize(payload.len() + hs.get_next_message_overhead(), 0);
                hs.write_message(&payload, buf).unwrap();
                println!("[{:?}] wrote handshake message", self.side);
                self.state.to_zero_rtt();

                None
            }
            (_, State::ZeroRtt(_)) => {
                self.state.to_handshake();
                // Initial hello sent out
                // Quinn expects its own Handshake set of keys so generate these.

                println!("[{:?}] generated handshake keys", self.side);

                // TODO: these are very likely not the keys we want to use, figure out a better construction
                Some(initial_keys(
                    VERSION,
                    &ConnectionId::new(&[0u8; 8]),
                    self.side,
                ))
            }
            (Side::Server, State::Handshake(ref mut hs)) => {
                // Send handshake response.
                assert!(self.handshake_data_remote.is_some());
                // respond
                let handshake_data_remote = self.handshake_data_remote.as_ref().unwrap();
                let response = HandshakeData::Server {
                    alpn_protocol: handshake_data_remote.select_alpn_protocol(&self.alpn_protocols),
                    server_name: None, // TODO:
                    transport_parameters: self.params_local.clone(),
                };

                let payload = response.as_bytes();
                buf.resize(payload.len() + hs.get_next_message_overhead(), 0);
                hs.write_message(&payload, buf).unwrap();
                assert!(hs.completed());

                let hs = self.state.to_data();
                let (keys, next_secrets) = keys_from_handshake_state(&hs, self.side);
                println!("[{:?}] generated secure keys", self.side);
                self.next_secrets = Some(next_secrets);
                Some(keys)
            }
            (_, State::OneRtt(ref mut hs)) => {
                println!("{:?} {:?}", self.side, hs.completed());
                assert!(hs.completed());
                /*if self.side == Side::Client {
                    // Finish the handshake
                    // TODO: can this be optimized?
                    buf.resize(hs.get_next_message_overhead(), 0);
                    hs.write_message(&[], buf).unwrap();
                }*/
                // Handshake finished.
                // We can now generate the final data keys.

                let hs = self.state.to_data();
                let (keys, next_secrets) = keys_from_handshake_state(&hs, self.side);
                println!("[{:?}] generated secure keys", self.side);
                self.next_secrets = Some(next_secrets);

                Some(keys)
            }
            (_, _) => None,
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        let secrets = self.next_secrets.as_mut()?;
        let keys = secrets.next_packet_keys();

        Some(keys)
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
                return Err("handshakedata: side missmatch");
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
                    TransportParameters::read(!side, &mut std::io::Cursor::new(&bytes[pos..]))
                        .map_err(|e| {
                            dbg!(e);
                            "invalid transport parameters"
                        })?;

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
                    TransportParameters::read(!side, &mut std::io::Cursor::new(&bytes[pos..]))
                        .map_err(|e| {
                            dbg!(e);
                            "invalid transport parameters"
                        })?;

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
    pub remote_public_key: DhPublicKey,
    pub local_private_key: DhPrivateKey,
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

        let mut builder = HandshakeStateBuilder::new();
        builder
            .set_pattern(noise_protocol::patterns::noise_ik())
            .set_is_initiator(true) // Client initiates
            .set_prologue(&[]) // No prologue for now
            .set_s(U8Array::clone(&self.local_private_key)) // Local Static Key (Private)
            .set_rs(U8Array::clone(&self.remote_public_key)); // Remote Static Key (Public)

        let handshake = builder.build_handshake_state();

        Ok(Box::new(NquicSession {
            handshake_data_remote: None,
            params_local: params.clone(),
            alpn_protocols: self.alpn_protocols.clone(),
            side: Side::Client,
            state: State::Initial(handshake),
            next_secrets: None,
        }))
    }
}

pub struct ServerConfig {
    /// Available ALPN protocol names.
    /// Ordered by most perferred first.
    pub alpn_protocols: Vec<Vec<u8>>,
    pub local_private_key: DhPrivateKey,
}

impl crypto::ServerConfig for ServerConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        debug_assert_eq!(version, VERSION);

        let mut builder = HandshakeStateBuilder::new();
        builder
            .set_pattern(noise_protocol::patterns::noise_ik())
            .set_is_initiator(false) // Server responds
            .set_prologue(&[]) // No prologue for now
            .set_s(U8Array::clone(&self.local_private_key)); // Local Static Key (Private)

        let handshake = builder.build_handshake_state();

        Box::new(NquicSession {
            handshake_data_remote: None,
            params_local: params.clone(),
            alpn_protocols: self.alpn_protocols.clone(),
            side: Side::Server,
            state: State::Initial(handshake),
            next_secrets: None,
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

struct Secret {
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

    fn next_packet_keys(&mut self) -> KeyPair<Box<dyn crypto::PacketKey>> {
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

fn keys_from_handshake_state(hs: &HandshakeState, side: Side) -> (Keys, Secret) {
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

fn protocol_violation(reason: impl Into<String>) -> TransportError {
    TransportError {
        code: TransportErrorCode::PROTOCOL_VIOLATION,
        frame: None,
        reason: reason.into(),
    }
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
        let mut local_private_key = DhKeypair::default();
        let server_config = ServerConfig {
            alpn_protocols: vec![b"hello".to_vec()],
            local_private_key: local_private_key.private,
        };

        let mut rng = rand::thread_rng();
        let dest_cid = ConnectionId::new(&[1, 2, 3]);
        let mut packet = [0u8; 128];
        rng.fill_bytes(&mut packet);

        let retry_tag = server_config.retry_tag(VERSION, &dest_cid, &packet);

        // TODO: figure out how to test this
        // assert!(is_valid_retry(&dest_cid, &packet[..16] retry_tag))
    }

    #[test]
    fn test_handshake() {
        let builder = || {
            let mut builder = HandshakeStateBuilder::<X25519>::new();
            builder
                .set_pattern(noise_protocol::patterns::noise_ik())
                .set_prologue(&[]);
            builder
        };

        let key_r = DhKeypair::default();
        let key_i = DhKeypair::default();

        let mut b = builder();
        b.set_is_initiator(true)
            .set_s(key_i.private)
            .set_rs(U8Array::clone(&key_r.public));
        let mut handshake_i = b.build_handshake_state::<Aes256Gcm, Sha256>();

        let mut b = builder();
        b.set_is_initiator(false).set_s(key_r.private);
        let mut handshake_r = b.build_handshake_state::<Aes256Gcm, Sha256>();

        let buf = handshake_i.write_message_vec(b"hello").unwrap();
        let msg = handshake_r.read_message_vec(&buf).unwrap();
        assert_eq!(&msg, b"hello");

        let buf = handshake_r.write_message_vec(&[]).unwrap();
        let msg = handshake_i.read_message_vec(&buf).unwrap();
        assert!(msg.is_empty());

        assert!(handshake_i.completed());
        assert!(handshake_r.completed());
    }
}
