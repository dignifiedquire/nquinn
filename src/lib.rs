pub mod rustcrypto;
mod session;

pub use self::session::*;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use snow::resolvers::CryptoResolver;

    use crate::rustcrypto::{HandshakeTokenKey, HmacKey};

    use super::*;

    const TEST_ALPN: &[u8] = b"nquic-test";

    /// Generates a Curve25519 Keypair, as used by noise.
    fn generate_keypair() -> Box<dyn snow::types::Dh> {
        let resolver = snow::resolvers::DefaultResolver::default();
        resolver
            .resolve_dh(&snow::params::DHChoice::Curve25519)
            .unwrap()
    }

    #[tokio::test]
    async fn minimal() {
        let (mut server_ep, server_key) = {
            let key = generate_keypair();
            let nquic_server_config = ServerConfig {
                alpn_protocols: vec![TEST_ALPN.to_vec()],
                local_private_key: key.privkey().try_into().unwrap(),
            };
            let server_config = quinn::ServerConfig::new(
                Arc::new(nquic_server_config),
                Arc::new(HandshakeTokenKey::default()),
            );
            let server_socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
            let ep = quinn::Endpoint::new(
                quinn::EndpointConfig::new(Arc::new(HmacKey::default())),
                Some(server_config),
                server_socket,
                quinn::TokioRuntime,
            )
            .unwrap();

            (ep, key)
        };

        let (mut client_ep, client_key) = {
            let key = generate_keypair();
            let nquic_client_config = ClientConfig {
                alpn_protocols: vec![TEST_ALPN.to_vec()],
                local_private_key: key.privkey().try_into().unwrap(),
                remote_public_key: server_key.pubkey().try_into().unwrap(),
            };
            let client_config = quinn::ClientConfig::new(Arc::new(nquic_client_config));
            let client_socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
            let ep = quinn::Endpoint::new(
                quinn::EndpointConfig::new(Arc::new(HmacKey::default())),
                None,
                client_socket,
                quinn::TokioRuntime,
            )
            .unwrap();
            (ep, key)
        };

        // TODO: connect & send back and forth
    }
}
