use std::time::{Instant, Duration};
use wire_core::{Stack, MacAddress, Ipv4Address, TcpHeader, TcpFlags, Seq, checksum, tcp_checksum};
use wire_sim::{SimConfig, run_simulation};

fn main() {
    println!("\x1b[1;36m================================================================================\x1b[0m");
    println!("\x1b[1;37m                       WIRE TCP/IP STACK BENCHMARK SUITE                        \x1b[0m");
    println!("\x1b[1;36m================================================================================\x1b[0m\n");

    bench_checksum();
    println!();
    bench_fsm_throughput();
    println!();
    bench_simulation_chaos();
    println!();

    println!("\x1b[1;36m================================================================================\x1b[0m");
    println!("\x1b[1;32m                          ALL BENCHMARKS COMPLETED                              \x1b[0m");
    println!("\x1b[1;36m================================================================================\x1b[0m");
}

fn bench_checksum() {
    println!("\x1b[1;33m[1/3] Internet Checksum (RFC 1071) Computation Performance\x1b[0m");
    println!("--------------------------------------------------------------------------------");
    
    let chunk_size = 1460;
    let iterations = 1_000_000;
    let data = vec![0x5au8; chunk_size];
    let total_bytes = chunk_size as u64 * iterations as u64;

    let start = Instant::now();
    let mut dummy_sum = 0u16;
    for _ in 0..iterations {
        dummy_sum = dummy_sum.wrapping_add(checksum(&data));
    }
    let elapsed = start.elapsed();
    std::hint::black_box(dummy_sum);

    let mb_processed = (total_bytes as f64) / (1024.0 * 1024.0);
    let gbps = (total_bytes as f64 * 8.0) / (elapsed.as_secs_f64() * 1_000_000_000.0);
    let ns_per_op = elapsed.as_nanos() as f64 / iterations as f64;

    println!("  Payload Size:          {} bytes (MSS)", chunk_size);
    println!("  Iterations:            {}", iterations);
    println!("  Total Processed:       {:.2} MB", mb_processed);
    println!("  Elapsed Time:          {:.3} ms", elapsed.as_secs_f64() * 1000.0);
    println!("  Latency:               \x1b[1;32m{:.2} ns/chunk\x1b[0m", ns_per_op);
    println!("  Throughput:            \x1b[1;32m{:.2} Gbps\x1b[0m", gbps);
}

fn bench_fsm_throughput() {
    println!("\x1b[1;33m[2/3] Pure Core State-Machine Ingress Packet Throughput\x1b[0m");
    println!("--------------------------------------------------------------------------------");

    let mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip = Ipv4Address([192, 168, 99, 2]);
    let mut stack = Stack::new(mac, ip);
    stack.listen(8080);

    let client_mac = MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let client_ip = Ipv4Address([192, 168, 99, 1]);
    stack.arp_cache.insert(client_ip, client_mac);

    let now = Instant::now();
    let syn_hdr = TcpHeader {
        src_port: 50000,
        dst_port: 8080,
        seq: Seq(100),
        ack: Seq(0),
        data_offset: 5,
        flags: TcpFlags::SYN,
        window: 65535,
        checksum: 0,
        options: Vec::new(),
    };
    let mut syn_bytes = syn_hdr.serialize();
    let csum = tcp_checksum(client_ip, ip, &syn_bytes);
    syn_bytes[16..18].copy_from_slice(&csum.to_be_bytes());

    let mut syn_frame = vec![0u8; 14 + 20 + syn_bytes.len()];
    syn_frame[0..6].copy_from_slice(&mac.0);
    syn_frame[6..12].copy_from_slice(&client_mac.0);
    syn_frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    syn_frame[14] = 0x45;
    let total_len = (20 + syn_bytes.len()) as u16;
    syn_frame[16..18].copy_from_slice(&total_len.to_be_bytes());
    syn_frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
    syn_frame[22] = 64;
    syn_frame[23] = 6;
    syn_frame[26..30].copy_from_slice(&client_ip.0);
    syn_frame[30..34].copy_from_slice(&ip.0);
    let ip_csum = checksum(&syn_frame[14..34]);
    syn_frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    syn_frame[34..].copy_from_slice(&syn_bytes);

    stack.on_packet(&syn_frame, now);
    stack.tx_queue.clear();

    let ack_hdr = TcpHeader {
        src_port: 50000,
        dst_port: 8080,
        seq: Seq(101),
        ack: Seq(21246687),
        data_offset: 5,
        flags: TcpFlags::ACK,
        window: 65535,
        checksum: 0,
        options: Vec::new(),
    };
    let mut ack_bytes = ack_hdr.serialize();
    let csum = tcp_checksum(client_ip, ip, &ack_bytes);
    ack_bytes[16..18].copy_from_slice(&csum.to_be_bytes());
    let mut ack_frame = syn_frame.clone();
    ack_frame[34..].copy_from_slice(&ack_bytes);
    stack.on_packet(&ack_frame, now);
    stack.tx_queue.clear();

    let payload = vec![0x42u8; 1024];
    let data_hdr = TcpHeader {
        src_port: 50000,
        dst_port: 8080,
        seq: Seq(101),
        ack: Seq(21246687),
        data_offset: 5,
        flags: TcpFlags::ACK | TcpFlags::PSH,
        window: 65535,
        checksum: 0,
        options: Vec::new(),
    };
    let mut data_seg = data_hdr.serialize();
    data_seg.extend_from_slice(&payload);
    let csum = tcp_checksum(client_ip, ip, &data_seg);
    data_seg[16..18].copy_from_slice(&csum.to_be_bytes());

    let mut data_frame = vec![0u8; 14 + 20 + data_seg.len()];
    data_frame[0..6].copy_from_slice(&mac.0);
    data_frame[6..12].copy_from_slice(&client_mac.0);
    data_frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    data_frame[14] = 0x45;
    let total_len = (20 + data_seg.len()) as u16;
    data_frame[16..18].copy_from_slice(&total_len.to_be_bytes());
    data_frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
    data_frame[22] = 64;
    data_frame[23] = 6;
    data_frame[26..30].copy_from_slice(&client_ip.0);
    data_frame[30..34].copy_from_slice(&ip.0);
    let ip_csum = checksum(&data_frame[14..34]);
    data_frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    data_frame[34..].copy_from_slice(&data_seg);

    let iterations = 200_000;
    let start = Instant::now();
    for _ in 0..iterations {
        stack.on_packet(&data_frame, now);
        stack.tx_queue.clear();
    }
    let elapsed = start.elapsed();

    let pps = (iterations as f64) / elapsed.as_secs_f64();
    let ns_per_pkt = elapsed.as_nanos() as f64 / iterations as f64;
    let mb_rate = (iterations as f64 * 1024.0) / (elapsed.as_secs_f64() * 1024.0 * 1024.0);

    println!("  Inbound Segment:       1024 bytes payload + L2/L3/L4 headers");
    println!("  Packets Processed:     {}", iterations);
    println!("  Ingress Latency:       \x1b[1;32m{:.2} ns/packet\x1b[0m", ns_per_pkt);
    println!("  Packet Ingress Rate:   \x1b[1;32m{:.2} Mpps\x1b[0m", pps / 1_000_000.0);
    println!("  Processing Rate:       \x1b[1;32m{:.2} MB/s\x1b[0m", mb_rate);
}

fn bench_simulation_chaos() {
    println!("\x1b[1;33m[3/3] Deterministic Chaos Simulation Transfer Engine\x1b[0m");
    println!("--------------------------------------------------------------------------------");
    println!("  {:<18} | {:<10} | {:<12} | {:<14} | {:<10}", "Scenario", "Loss/Dup", "Payload", "Duration", "Sim Pkts/sec");
    println!("--------------------------------------------------------------------------------");

    let runs = vec![
        ("Clean Wire", 0.0, 0.0, 1_048_576),
        ("1% Packet Loss", 0.01, 0.0, 524_288),
        ("5% Loss + 2% Dup", 0.05, 0.02, 262_144),
    ];

    for (name, loss, dup, data_size) in runs {
        let config = SimConfig {
            loss_rate: loss,
            dup_rate: dup,
            min_delay: Duration::from_micros(10),
            max_delay: Duration::from_micros(200),
            data_size,
            max_ticks: 5_000_000,
        };

        let start = Instant::now();
        let res = run_simulation(42, &config);
        let elapsed = start.elapsed();

        let sim_pps = (res.ticks as f64) / elapsed.as_secs_f64();

        println!("  \x1b[1;37m{:<18}\x1b[0m | {:<4}%/{:<3}% | {:<10} KB | \x1b[1;32m{:<10.2} ms\x1b[0m | \x1b[1;32m{:<8.2} Kpps\x1b[0m",
            name,
            (loss * 100.0) as u32,
            (dup * 100.0) as u32,
            data_size / 1024,
            elapsed.as_secs_f64() * 1000.0,
            sim_pps / 1000.0
        );
    }
}
