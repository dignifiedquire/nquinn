pub mod rustcrypto;
mod session;

pub use self::session::*;

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use rand::RngCore;

    use crate::rustcrypto::{HandshakeTokenKey, HmacKey};

    use super::*;

    const TEST_ALPN: &[u8] = b"nquic-test";

    #[tokio::test]
    async fn minimal() {
        let (mut server_ep, server_key) = {
            let key = generate_keypair();
            let nquic_server_config = ServerConfig {
                alpn_protocols: vec![TEST_ALPN.to_vec()],
                local_private_key: key.private.clone().try_into().unwrap(),
            };
            let server_config = quinn::ServerConfig::new(
                Arc::new(nquic_server_config),
                Arc::new(HandshakeTokenKey::default()),
            );
            let server_socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
            let mut ep_config = quinn::EndpointConfig::new(Arc::new(HmacKey::default()));
            ep_config.supported_versions(vec![VERSION.clone()]);
            let ep = quinn::Endpoint::new(
                ep_config,
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
                local_private_key: key.private.clone().try_into().unwrap(),
                remote_public_key: server_key.public.try_into().unwrap(),
            };
            let mut client_config = quinn::ClientConfig::new(Arc::new(nquic_client_config));
            client_config.version(VERSION);
            let client_socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
            let mut ep_config = quinn::EndpointConfig::new(Arc::new(HmacKey::default()));
            ep_config.supported_versions(vec![VERSION.clone()]);
            let mut ep =
                quinn::Endpoint::new(ep_config, None, client_socket, quinn::TokioRuntime).unwrap();
            ep.set_default_client_config(client_config);
            (ep, key)
        };

        macro_rules! roundtrip {
            ($a:expr, $b:expr, $msg:expr) => {
                let a = $a.clone();
                let b = $b.clone();
                let a_name = "client";
                let b_name = "server";
                println!("{} -> {} ({} bytes)", a_name, b_name, $msg.len());
                let a_addr =
                    SocketAddr::new("127.0.0.1".parse().unwrap(), a.local_addr().unwrap().port());
                let b_addr =
                    SocketAddr::new("127.0.0.1".parse().unwrap(), b.local_addr().unwrap().port());
                println!(
                    "{}: {}, {}: {}",
                    a_name,
                    a_addr,
                    b_name,
                    b.local_addr().unwrap()
                );

                let b_task = tokio::task::spawn(async move {
                    println!("[{}] accepting conn", b_name);
                    while let Some(conn) = b.accept().await {
                        println!("[{}] connecting", b_name);
                        let conn = conn.await.expect(&format!("[{}] connecting", b_name));
                        println!("[{}] accepting bi", b_name);
                        let (mut send_bi, recv_bi) = conn
                            .accept_bi()
                            .await
                            .expect(&format!("[{}] accepting bi", b_name));

                        println!("[{}] reading", b_name);
                        let val = recv_bi
                            .read_to_end(usize::MAX)
                            .await
                            .expect(&format!("[{}] reading to end", b_name));
                        send_bi
                            .finish()
                            .await
                            .expect(&format!("[{}] finishing", b_name));
                        println!("[{}] finished", b_name);
                        return val;
                    }
                    panic!("no connections available anymore");
                });

                println!("[{}] connecting to {}", a_name, b_addr);
                let conn = a
                    .connect(b_addr, "localhost")
                    .unwrap()
                    .await
                    .expect(&format!("[{}] connect", a_name));

                println!("[{}] opening bi", a_name);
                let (mut send_bi, recv_bi) = conn
                    .open_bi()
                    .await
                    .expect(&format!("[{}] open bi", a_name));
                println!("[{}] writing message", a_name);
                send_bi
                    .write_all(&$msg[..])
                    .await
                    .expect(&format!("[{}] write all", a_name));

                println!("[{}] finishing", a_name);
                send_bi
                    .finish()
                    .await
                    .expect(&format!("[{}] finish", a_name));

                println!("[{}] reading_to_end", a_name);
                let _ = recv_bi
                    .read_to_end(usize::MAX)
                    .await
                    .expect(&format!("[{}]", a_name));
                println!("[{}] close", a_name);
                conn.close(0u32.into(), b"done");
                println!("[{}] wait idle", a_name);
                a.wait_idle().await;

                drop(send_bi);

                // make sure the right values arrived
                println!("waiting for channel");
                let val = b_task.await.unwrap();
                assert!(
                    val == $msg,
                    "expected {}, got {}",
                    hex::encode($msg),
                    hex::encode(val)
                );
            };
        }

        for i in 0..10 {
            println!("-- round {}", i + 1);
            roundtrip!(client_ep, server_ep, b"hello");
        }

        println!("-- larger data");
        {
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            roundtrip!(client_ep, server_ep, data);
        }
    }
}
