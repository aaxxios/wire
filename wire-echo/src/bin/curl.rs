use std::time::{Instant, Duration};
use wire_core::{Stack, MacAddress, Ipv4Address, TcpState, build_dns_query, parse_dns_response};
use wire_tap::TapDevice;

enum CurlStage {
    DnsQuery,
    Connecting(wire_core::SocketTuple),
    Connected(wire_core::SocketTuple),
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let target = if args.len() > 1 { &args[1] } else { "http://192.168.99.1:8000/index.html" };

    let url_str = target.strip_prefix("http://").unwrap_or(target);
    let (host_port, path) = match url_str.find('/') {
        Some(idx) => (&url_str[..idx], &url_str[idx..]),
        None => (url_str, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(idx) => (&host_port[..idx], host_port[idx + 1..].parse::<u16>().unwrap_or(80)),
        None => (host_port, 80),
    };

    let is_ip = host.parse::<std::net::Ipv4Addr>().is_ok();

    let mut tap = TapDevice::new("tap0")?;
    let local_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let local_ip = Ipv4Address([192, 168, 99, 2]);
    let dns_server = Ipv4Address([192, 168, 99, 1]);

    let mut stack = Stack::new(local_mac, local_ip);
    let mut buf = [0u8; 2048];
    let mut last_tick = Instant::now();

    let mut stage = if is_ip {
        let ip_parsed = host.parse::<std::net::Ipv4Addr>().unwrap();
        let target_ip = Ipv4Address(ip_parsed.octets());
        let tuple = stack.tcp_connect(target_ip, port, 49200, Instant::now());
        CurlStage::Connecting(tuple)
    } else {
        println!("🔍 Resolving DNS for '{}' via {}.{}.{}.{}...", host, dns_server.0[0], dns_server.0[1], dns_server.0[2], dns_server.0[3]);
        let query = build_dns_query(host, 0x1234);
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

        match &stage {
            CurlStage::DnsQuery => {
                if let Some((_src_ip, _src_port, data)) = stack.udp_recv(53000) {
                    if let Some(resolved_ip) = parse_dns_response(&data) {
                        println!("✅ Resolved {} -> {}.{}.{}.{}", host, resolved_ip.0[0], resolved_ip.0[1], resolved_ip.0[2], resolved_ip.0[3]);
                        let tuple = stack.tcp_connect(resolved_ip, port, 49201, now);
                        stage = CurlStage::Connecting(tuple);
                    }
                }
            }
            CurlStage::Connecting(tuple) => {
                if let Some(TcpState::Established) = stack.connection_state(*tuple) {
                    println!("⚡ Connected to {}:{}", host, port);
                    let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, host);
                    stack.tcp_send(*tuple, req.as_bytes());
                    stack.flush(now);
                    request_sent = true;
                    stage = CurlStage::Connected(*tuple);
                }
            }
            CurlStage::Connected(tuple) => {
                let data = stack.tcp_recv(*tuple);
                if !data.is_empty() {
                    response_bytes.extend(&data);
                }
                if let Some(TcpState::CloseWait) = stack.connection_state(*tuple) {
                    stack.tcp_close(*tuple, now);
                }
                let state = stack.connection_state(*tuple);
                if (state.is_none() || state == Some(TcpState::Closed)) && request_sent && !response_bytes.is_empty() {
                    break;
                }
            }
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
