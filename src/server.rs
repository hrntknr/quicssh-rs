use clap::Parser;
use quinn::{Endpoint, ServerConfig};

use log::{debug, error, info};
use std::error::Error;
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Parser, Debug)]
#[clap(name = "server")]
pub struct Opt {
    /// Address to listen on
    #[clap(long = "listen", short = 'l', default_value = "0.0.0.0:4433")]
    listen: SocketAddr,
    /// Address of the ssh server
    #[clap(long = "proxy-to", short = 'p', default_value = "127.0.0.1:22")]
    proxy_to: SocketAddr,
    /// Idle timeout in seconds
    #[clap(long = "idle", short = 'i', default_value = "60")]
    idle: u64,
    // Keep alive interval in seconds
    #[clap(long = "keep-alive", short = 'k', default_value = "1")]
    keep_alive: u64,
}

/// Returns default server configuration along with its certificate.
fn configure_server(idle: u64, keep_alive: u64) -> Result<(ServerConfig, Vec<u8>), Box<dyn Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der.clone())];

    let mut server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());
    transport_config.max_idle_timeout(Some(Duration::from_secs(idle).try_into()?));
    transport_config.max_backoff_exponent(0);
    if keep_alive > 0 {
        transport_config.keep_alive_interval(Some(Duration::from_secs(keep_alive)));
    }
    #[cfg(any(windows, os = "linux"))]
    transport_config.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));

    Ok((server_config, cert_der))
}

#[allow(unused)]
pub fn make_server_endpoint(
    bind_addr: SocketAddr,
    idle: u64,
    keep_alive: u64,
) -> Result<(Endpoint, Vec<u8>), Box<dyn Error>> {
    let (server_config, server_cert) = configure_server(idle, keep_alive)?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok((endpoint, server_cert))
}

#[tokio::main]
pub async fn run(options: Opt) -> Result<(), Box<dyn Error>> {
    let (endpoint, _) =
        make_server_endpoint(options.listen, options.idle, options.keep_alive).unwrap();
    // accept a single connection
    loop {
        let incoming_conn = match endpoint.accept().await {
            Some(conn) => conn,
            None => {
                continue;
            }
        };
        let conn = match incoming_conn.await {
            Ok(conn) => conn,
            Err(e) => {
                error!("[server] accept connection error: {}", e);
                continue;
            }
        };

        info!(
            "[server] connection accepted: addr={}",
            conn.remote_address()
        );
        tokio::spawn(async move {
            handle_connection(options.proxy_to, conn).await;
        });
        // Dropping all handles associated with a connection implicitly closes it
    }
}

async fn handle_connection(proxy_for: SocketAddr, connection: quinn::Connection) {
    let ssh_stream = TcpStream::connect(proxy_for).await;
    let ssh_conn = match ssh_stream {
        Ok(conn) => conn,
        Err(e) => {
            error!("[server] connect to ssh error: {}", e);
            return;
        }
    };

    info!("[server] ssh connection established");

    let (mut quinn_send, mut quinn_recv) = match connection.accept_bi().await {
        Ok(stream) => stream,
        Err(e) => {
            error!("[server] open quic stream error: {}", e);
            return;
        }
    };

    let (mut ssh_recv, mut ssh_write) = tokio::io::split(ssh_conn);

    let recv_thread = async move {
        let mut buf = [0; 2048];
        loop {
            match ssh_recv.read(&mut buf).await {
                Ok(n) => {
                    if n == 0 {
                        continue;
                    }
                    debug!("[server] recv data from ssh server {} bytes", n);
                    match quinn_send.write_all(&buf[..n]).await {
                        Ok(_) => (),
                        Err(e) => {
                            error!("[server] writing to quic stream error: {}", e);
                            return;
                        }
                    }
                }
                Err(e) => {
                    error!("[server] reading from ssh server error: {}", e);
                    return;
                }
            }
        }
    };

    let write_thread = async move {
        let mut buf = [0; 2048];
        loop {
            match quinn_recv.read(&mut buf).await {
                Ok(None) => {
                    continue;
                }
                Ok(Some(n)) => {
                    debug!("[server] recv data from quic stream {} bytes", n);
                    if n == 0 {
                        return;
                    }
                    match ssh_write.write_all(&buf[..n]).await {
                        Ok(_) => (),
                        Err(e) => {
                            error!("[server] writing to ssh server error: {}", e);
                            return;
                        }
                    }
                }
                Err(e) => {
                    error!("[server] reading from quic client error: {}", e);
                    return;
                }
            }
        }
    };

    tokio::select! {
        _ = recv_thread => (),
        _ = write_thread => (),
    }

    info!("[server] exit client");

    // tokio::join!(recv_thread, write_thread);
}
