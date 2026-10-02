use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};
use rustls::{ClientConfig, ClientConnection};
use wire_core::{build_dns_query, parse_dns_response, Ipv4Address, MacAddress, SocketTuple, Stack, TcpState};
use wire_tap::TapDevice;

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

enum CurlStage {
    DnsQuery,
    Connecting { tuple: SocketTuple, secure: bool, host: String },
    TlsHandshake { tuple: SocketTuple, tls: ClientConnection, path: String, host: String },
    Connected { tuple: SocketTuple, tls: Option<ClientConnection> },
    Done,
}

fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args: Vec<String> = std::env::args().collect();
    let target = if args.len() > 1 { &args[1] } else { "http://192.168.99.1:8000/index.html" };

    let secure = target.starts_with("https://");
    let url_str = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
        .unwrap_or(target);

    let (host_port, path) = match url_str.find('/') {
        Some(idx) => (&url_str[..idx], url_str[idx..].to_string()),
        None => (url_str, "/".to_string()),
    };

    let (host, port) = match host_port.find(':') {
        Some(idx) => (
            host_port[..idx].to_string(),
            host_port[idx + 1..].parse::<u16>().unwrap_or(if secure { 443 } else { 80 }),
        ),
        None => (host_port.to_string(), if secure { 443 } else { 80 }),
    };

    let is_ip = host.parse::<std::net::Ipv4Addr>().is_ok();

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    let config_arc = Arc::new(config);

    let mut tap = TapDevice::new("tap0")?;
    let local_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let local_ip = Ipv4Address([192, 168, 99, 2]);
    let gateway_ip = Ipv4Address([192, 168, 99, 1]);
    let dns_server = Ipv4Address([192, 168, 99, 1]);

    let mut stack = Stack::new(local_mac, local_ip, gateway_ip);
    let mut buf = [0u8; 2048];
    let mut last_tick = Instant::now();

    let mut stage = if is_ip {
        let ip_parsed = host.parse::<std::net::Ipv4Addr>().unwrap();
        let target_ip = Ipv4Address(ip_parsed.octets());
        let tuple = stack.tcp_connect(target_ip, port, 49200, Instant::now());
        CurlStage::Connecting { tuple, secure, host: host.clone() }
    } else {
        let query = build_dns_query(&host, 0x1234);
        stack.udp_send(dns_server, 53, 53000, &query);
        CurlStage::DnsQuery
    };

    let mut response_bytes = Vec::new();
    let mut request_sent = false;

    loop {
        let now = Instant::now();
        if now.duration_since(last_tick) >= Duration::from_millis(10) {
            stack.on_tick(now);
            last_tick = now;
        }

        let mut read_any = false;
        while let Some(n) = tap.poll_read(&mut buf)? {
            stack.on_packet(&buf[..n], now);
            read_any = true;
        }

        let mut next_stage = None;

        match &mut stage {
            CurlStage::DnsQuery => {
                if let Some((_src_ip, _src_port, data)) = stack.udp_recv(53000) {
                    if let Some(resolved_ip) = parse_dns_response(&data) {
                        let tuple = stack.tcp_connect(resolved_ip, port, 49201, now);
                        next_stage = Some(CurlStage::Connecting { tuple, secure, host: host.clone() });
                    }
                }
            }
            CurlStage::Connecting { tuple, secure: is_sec, host: h } => {
                if let Some(TcpState::Established) = stack.connection_state(*tuple) {
                    if *is_sec {
                        let server_name = rustls::pki_types::ServerName::try_from(h.clone())
                            .unwrap_or_else(|_| rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap())
                            .to_owned();
                        let tls = ClientConnection::new(config_arc.clone(), server_name)?;
                        next_stage = Some(CurlStage::TlsHandshake {
                            tuple: *tuple,
                            tls,
                            path: path.clone(),
                            host: h.clone(),
                        });
                    } else {
                        let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, h);
                        stack.tcp_send(*tuple, req.as_bytes());
                        stack.flush(now);
                        request_sent = true;
                        next_stage = Some(CurlStage::Connected { tuple: *tuple, tls: None });
                    }
                }
            }
            CurlStage::TlsHandshake { tuple, tls, path: p, host: h } => {
                if let Some(TcpState::Established) = stack.connection_state(*tuple) {
                    while tls.wants_write() {
                        let mut write_buf = Vec::new();
                        tls.write_tls(&mut write_buf)?;
                        stack.tcp_send(*tuple, &write_buf);
                        stack.flush(now);
                    }

                    let rx_data = stack.tcp_recv(*tuple);
                    if !rx_data.is_empty() {
                        let mut slice = &rx_data[..];
                        tls.read_tls(&mut slice)?;
                        tls.process_new_packets()?;
                    }

                    if !tls.is_handshaking() {
                        let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", p, h);
                        let _ = tls.writer().write_all(req.as_bytes());
                        let mut write_buf = Vec::new();
                        tls.write_tls(&mut write_buf)?;
                        stack.tcp_send(*tuple, &write_buf);
                        stack.flush(now);
                        request_sent = true;
                        
                        let current_stage = std::mem::replace(&mut stage, CurlStage::Done);
                        if let CurlStage::TlsHandshake { tuple, tls, .. } = current_stage {
                            stage = CurlStage::Connected { tuple, tls: Some(tls) };
                        }
                    }
                }
            }
            CurlStage::Connected { tuple, tls } => {
                let rx_data = stack.tcp_recv(*tuple);
                if !rx_data.is_empty() {
                    if let Some(tls_conn) = tls {
                        let mut slice = &rx_data[..];
                        tls_conn.read_tls(&mut slice)?;
                        tls_conn.process_new_packets()?;
                        let mut plain_out = vec![0u8; 4096];
                        while let Ok(n) = tls_conn.reader().read(&mut plain_out) {
                            if n == 0 { break; }
                            response_bytes.extend(&plain_out[..n]);
                        }
                    } else {
                        response_bytes.extend(&rx_data);
                    }
                }
                if let Some(TcpState::CloseWait) = stack.connection_state(*tuple) {
                    stack.tcp_close(*tuple, now);
                }
                let state = stack.connection_state(*tuple);
                if (state.is_none() || state == Some(TcpState::Closed)) && request_sent && !response_bytes.is_empty() {
                    break;
                }
            }
            CurlStage::Done => break,
        }

        if let Some(next) = next_stage {
            stage = next;
        }

        while let Some(mut tx_packet) = stack.tx_queue.pop_front() {
            stack.resolve_and_populate_dst_mac(&mut tx_packet);
            match tap.write_async(&tx_packet)? {
                Some(_) => {}
                None => {
                    stack.tx_queue.push_front(tx_packet);
                    break;
                }
            }
        }

        if !read_any {
            std::thread::sleep(Duration::from_micros(100));
        }
    }

    println!("\n=== WIRE-CURL RESPONSE BODY ===");
    println!("{}", String::from_utf8_lossy(&response_bytes));
    println!("===============================");

    Ok(())
}
