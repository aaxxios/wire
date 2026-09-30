use std::sync::Arc;
use std::thread;
use std::time::Instant;
use wire_core::{Stack, MacAddress, Ipv4Address};
use wire_xdp::{XdpSocket, XdpBpfModule, pin_thread_to_core};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    
    let bpf = Arc::new(XdpBpfModule::load_and_attach("veth-wire", &[])?);
    let cores = vec![0, 1];
    let mut handles = Vec::new();

    for (queue_id, &core_id) in cores.iter().enumerate() {
        let bpf = Arc::clone(&bpf);
        
        let handle = thread::spawn(move || -> anyhow::Result<()> {
            pin_thread_to_core(core_id)?;

            let mut xsk = XdpSocket::new("veth-wire", queue_id as u32)?;
            bpf.update_xsk_map(queue_id as u32, xsk.fd())?;

            let local_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
            let local_ip = Ipv4Address([192, 168, 99, 2]);
            let gateway_ip = Ipv4Address([192, 168, 99, 1]);
            
            let mut stack = Stack::new(local_mac, local_ip, gateway_ip);
            stack.listen(8080);
            let mut buf = [0u8; 2048];
            let mut last_tick = Instant::now();

            loop {
                let now = Instant::now();
                if now.duration_since(last_tick) >= std::time::Duration::from_millis(10) {
                    stack.on_tick(now);
                    last_tick = now;
                }

                let mut read_any = false;
                while let Some(n) = xsk.poll_read(&mut buf)? {
                    stack.on_packet(&buf[..n], now);
                    read_any = true;
                }

                for tuple in stack.active_connections() {
                    let data = stack.tcp_recv(tuple);
                    if !data.is_empty() {
                        stack.tcp_send(tuple, &data);
                        stack.flush(now);
                    }
                    if let Some(wire_core::TcpState::CloseWait) = stack.connection_state(tuple) {
                        stack.tcp_close(tuple, now);
                    }
                }

                while let Some(mut tx_packet) = stack.tx_queue.pop_front() {
                    stack.resolve_and_populate_dst_mac(&mut tx_packet);
                    match xsk.write_async(&tx_packet)? {
                        Some(_) => {}
                        None => {
                            stack.tx_queue.push_front(tx_packet);
                            break;
                        }
                    }
                }

                if !read_any {
                    std::thread::sleep(std::time::Duration::from_micros(10));
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap()?;
    }

    Ok(())
}
