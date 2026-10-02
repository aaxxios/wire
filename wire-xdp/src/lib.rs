use std::ptr;
use std::sync::atomic::{fence, Ordering};
use wire_core::probes::{self, StageId};

pub const NUM_FRAMES: usize = 4096;
pub const FRAME_SIZE: usize = 2048;
pub const UMEM_SIZE: usize = NUM_FRAMES * FRAME_SIZE; // 8MB
pub const BATCH_SIZE: usize = 64;

const SOL_XDP: libc::c_int = 283;
const XDP_UMEM_REG: libc::c_int = 3;
const XDP_UMEM_FILL_RING: libc::c_int = 5;
const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;
const XDP_RX_RING: libc::c_int = 1;
const XDP_TX_RING: libc::c_int = 2;
const XDP_MMAP_OFFSETS: libc::c_int = 1;
const XDP_COPY: u16 = 1 << 1;

const BPF_MAP_CREATE: i32 = 0;
const BPF_MAP_UPDATE_ELEM: i32 = 2;
const BPF_PROG_LOAD: i32 = 5;
const BPF_MAP_TYPE_XSKMAP: u32 = 17;
const BPF_PROG_TYPE_XDP: u32 = 6;

const MAP_HUGE_2MB: libc::c_int = 21 << 26;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct XdpUmemReg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct XdpRingOffset {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct XdpMmapOffsets {
    pub rx: XdpRingOffset,
    pub tx: XdpRingOffset,
    pub fr: XdpRingOffset,
    pub cr: XdpRingOffset,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrXdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

pub fn pin_thread_to_core(core_id: usize) -> anyhow::Result<()> {
    unsafe {
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core_id, &mut cpuset);
        let res = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpuset);
        if res != 0 {
            return Err(anyhow::anyhow!("Affinity error: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfMapAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfProgAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfMapOpAttr {
    map_fd: u32,
    key: u64,
    value: u64,
    flags: u64,
}

fn bpf_syscall(cmd: i32, attr: *const u8, size: usize) -> i32 {
    unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size) as i32 }
}

pub struct XdpBpfModule {
    pub map_fd: i32,
    pub prog_fd: i32,
}

impl XdpBpfModule {
    pub fn load_and_attach(ifname: &str, _elf_bytes: &[u8]) -> anyhow::Result<Self> {
        let mut map_attr = BpfMapAttr {
            map_type: BPF_MAP_TYPE_XSKMAP,
            key_size: 4,
            value_size: 4,
            max_entries: 64,
            map_flags: 0,
            inner_map_fd: 0,
            numa_node: 0,
            map_name: [0; 16],
        };
        map_attr.map_name[..8].copy_from_slice(b"xsks_map");
        let map_fd = bpf_syscall(BPF_MAP_CREATE, &map_attr as *const _ as *const u8, std::mem::size_of::<BpfMapAttr>());
        if map_fd < 0 {
            return Err(anyhow::anyhow!("Map init failed: {}", std::io::Error::last_os_error()));
        }

        let mut raw_insns = vec![
            0x61u8 | (1 << 3), 0x15u8, 0x00u8, 0x00u8, 0x10u8, 0x00u8, 0x00u8, 0x00u8,
            0x18u8, 0x11u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0xbfu8, 0x22u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x85u8, 0x00u8, 0x00u8, 0x00u8, 0x33u8, 0x00u8, 0x00u8, 0x00u8,
            0xb7u8, 0x00u8, 0x00u8, 0x00u8, 0x02u8, 0x00u8, 0x00u8, 0x00u8,
            0xbfu8, 0x21u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x18u8, 0x12u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0xb7u8, 0x33u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x85u8, 0x00u8, 0x00u8, 0x00u8, 0x33u8, 0x00u8, 0x00u8, 0x00u8,
            0xb7u8, 0x00u8, 0x00u8, 0x00u8, 0x02u8, 0x00u8, 0x00u8, 0x00u8,
            0x95u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
        ];

        let map_val = map_fd as u32;
        raw_insns[12..16].copy_from_slice(&map_val.to_ne_bytes());

        let license = b"GPL\0";
        let mut prog_attr = BpfProgAttr {
            prog_type: BPF_PROG_TYPE_XDP,
            insn_cnt: (raw_insns.len() / 8) as u32,
            insns: raw_insns.as_ptr() as u64,
            license: license.as_ptr() as u64,
            log_level: 0,
            log_size: 0,
            log_buf: 0,
            kern_version: 0,
            prog_flags: 0,
            prog_name: [0; 16],
        };
        prog_attr.prog_name[..8].copy_from_slice(b"xdp_xsk");

        let prog_fd = bpf_syscall(BPF_PROG_LOAD, &prog_attr as *const _ as *const u8, std::mem::size_of::<BpfProgAttr>());
        if prog_fd < 0 {
            unsafe { libc::close(map_fd) };
            return Err(anyhow::anyhow!("Prog load error: {}", std::io::Error::last_os_error()));
        }

        let ifindex = unsafe {
            let cname = std::ffi::CString::new(ifname)?;
            libc::if_nametoindex(cname.as_ptr())
        };
        if ifindex == 0 {
            return Err(anyhow::anyhow!("Interface not found: {}", ifname));
        }

        let nl_fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if nl_fd >= 0 {
            #[repr(C)]
            struct NlMsg {
                hdr: libc::nlmsghdr,
                ifi: libc::ifinfomsg,
                attr_hdr: libc::nlattr,
                xdp_hdr: libc::nlattr,
                fd_attr: libc::nlattr,
                fd_val: i32,
            }

            let mut ifi: libc::ifinfomsg = unsafe { std::mem::zeroed() };
            ifi.ifi_index = ifindex as i32;

            let msg = NlMsg {
                hdr: libc::nlmsghdr {
                    nlmsg_len: std::mem::size_of::<NlMsg>() as u32,
                    nlmsg_type: 16,
                    nlmsg_flags: (0x01 | 0x100 | 0x400) as u16,
                    nlmsg_seq: 1,
                    nlmsg_pid: 0,
                },
                ifi,
                attr_hdr: libc::nlattr {
                    nla_len: (std::mem::size_of::<libc::nlattr>() * 2 + std::mem::size_of::<i32>()) as u16,
                    nla_type: 43,
                },
                xdp_hdr: libc::nlattr {
                    nla_len: (std::mem::size_of::<libc::nlattr>() + std::mem::size_of::<i32>()) as u16,
                    nla_type: 1,
                },
                fd_attr: libc::nlattr {
                    nla_len: 8,
                    nla_type: 3,
                },
                fd_val: prog_fd,
            };
            unsafe {
                libc::send(nl_fd, &msg as *const _ as *const libc::c_void, std::mem::size_of::<NlMsg>(), 0);
                libc::close(nl_fd);
            }
        }

        Ok(Self { map_fd, prog_fd })
    }

    pub fn update_xsk_map(&self, queue_id: u32, xsk_fd: i32) -> anyhow::Result<()> {
        let attr = BpfMapOpAttr {
            map_fd: self.map_fd as u32,
            key: &queue_id as *const _ as u64,
            value: &xsk_fd as *const _ as u64,
            flags: 0,
        };
        let res = bpf_syscall(BPF_MAP_UPDATE_ELEM, &attr as *const _ as *const u8, std::mem::size_of::<BpfMapOpAttr>());
        if res < 0 {
            return Err(anyhow::anyhow!("Map update failed: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

pub struct XdpRing {
    producer: *mut u32,
    consumer: *mut u32,
    descs: *mut libc::c_void,
    size: u32,
    mask: u32,
}

impl XdpRing {
    pub unsafe fn new(mmap_ptr: *mut libc::c_void, offsets: &XdpRingOffset, size: u32) -> Self {
        Self {
            producer: (mmap_ptr as usize + offsets.producer as usize) as *mut u32,
            consumer: (mmap_ptr as usize + offsets.consumer as usize) as *mut u32,
            descs: (mmap_ptr as usize + offsets.desc as usize) as *mut libc::c_void,
            size,
            mask: size - 1,
        }
    }

    #[inline(always)]
    pub fn producer_index(&self) -> u32 {
        unsafe { ptr::read_volatile(self.producer) }
    }

    #[inline(always)]
    pub fn consumer_index(&self) -> u32 {
        unsafe { ptr::read_volatile(self.consumer) }
    }

    #[inline(always)]
    pub fn set_producer_index(&mut self, idx: u32) {
        unsafe { ptr::write_volatile(self.producer, idx) }
    }

    #[inline(always)]
    pub fn set_consumer_index(&mut self, idx: u32) {
        unsafe { ptr::write_volatile(self.consumer, idx) }
    }
}

pub struct XdpSocket {
    fd: i32,
    umem_area: *mut u8,
    is_hugepage: bool,
    rx_ring: XdpRing,
    tx_ring: XdpRing,
    fill_ring: XdpRing,
    comp_ring: XdpRing,
    rx_cons: u32,
    tx_prod: u32,
    fill_prod: u32,
    comp_cons: u32,
}

impl XdpSocket {
    pub fn new(ifname: &str, queue_id: u32) -> anyhow::Result<Self> {
        unsafe {
            let fd = libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0);
            if fd < 0 {
                return Err(anyhow::anyhow!("Socket creation error"));
            }

            let mut is_hugepage = true;
            let mut umem_area = libc::mmap(
                ptr::null_mut(),
                UMEM_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB | MAP_HUGE_2MB,
                -1,
                0,
            );

            if umem_area == libc::MAP_FAILED {
                is_hugepage = false;
                let mut aligned_ptr: *mut libc::c_void = ptr::null_mut();
                let ret = libc::posix_memalign(&mut aligned_ptr, 4096, UMEM_SIZE);
                if ret != 0 {
                    libc::close(fd);
                    return Err(anyhow::anyhow!("UMEM allocation failed"));
                }
                umem_area = aligned_ptr;
            }

            let _ = libc::mlock(umem_area, UMEM_SIZE);

            let reg = XdpUmemReg {
                addr: umem_area as u64,
                len: UMEM_SIZE as u64,
                chunk_size: FRAME_SIZE as u32,
                headroom: 0,
                flags: 0,
            };

            let res = libc::setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &reg as *const _ as *const libc::c_void, std::mem::size_of::<XdpUmemReg>() as u32);
            if res < 0 {
                if is_hugepage {
                    libc::munmap(umem_area, UMEM_SIZE);
                } else {
                    libc::free(umem_area);
                }
                libc::close(fd);
                return Err(anyhow::anyhow!("setsockopt REG failed"));
            }

            let ring_size: u32 = 2048;
            libc::setsockopt(fd, SOL_XDP, XDP_UMEM_FILL_RING, &ring_size as *const _ as *const libc::c_void, 4);
            libc::setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &ring_size as *const _ as *const libc::c_void, 4);
            libc::setsockopt(fd, SOL_XDP, XDP_RX_RING, &ring_size as *const _ as *const libc::c_void, 4);
            libc::setsockopt(fd, SOL_XDP, XDP_TX_RING, &ring_size as *const _ as *const libc::c_void, 4);

            let mut offsets = XdpMmapOffsets::default();
            let mut optlen = std::mem::size_of::<XdpMmapOffsets>() as u32;
            libc::getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, &mut offsets as *mut _ as *mut libc::c_void, &mut optlen);

            let fill_map = libc::mmap(ptr::null_mut(), (offsets.fr.desc + (ring_size as u64 * 8)) as usize, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_POPULATE, fd, 0x100000000);
            let comp_map = libc::mmap(ptr::null_mut(), (offsets.cr.desc + (ring_size as u64 * 8)) as usize, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_POPULATE, fd, 0x180000000);
            let rx_map = libc::mmap(ptr::null_mut(), (offsets.rx.desc + (ring_size as u64 * std::mem::size_of::<XdpDesc>() as u64)) as usize, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_POPULATE, fd, 0x000000000);
            let tx_map = libc::mmap(ptr::null_mut(), (offsets.tx.desc + (ring_size as u64 * std::mem::size_of::<XdpDesc>() as u64)) as usize, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_POPULATE, fd, 0x080000000);

            let rx_ring = XdpRing::new(rx_map, &offsets.rx, ring_size);
            let tx_ring = XdpRing::new(tx_map, &offsets.tx, ring_size);
            let fill_ring = XdpRing::new(fill_map, &offsets.fr, ring_size);
            let comp_ring = XdpRing::new(comp_map, &offsets.cr, ring_size);

            let ifindex = {
                let cname = std::ffi::CString::new(ifname)?;
                libc::if_nametoindex(cname.as_ptr())
            };

            let sxdp = SockAddrXdp {
                sxdp_family: 44,
                sxdp_flags: XDP_COPY,
                sxdp_ifindex: ifindex,
                sxdp_queue_id: queue_id,
                sxdp_shared_umem_fd: 0,
            };

            libc::bind(fd, &sxdp as *const _ as *const libc::sockaddr, std::mem::size_of::<SockAddrXdp>() as u32);

            let mut socket = Self {
                fd,
                umem_area: umem_area as *mut u8,
                is_hugepage,
                rx_ring,
                tx_ring,
                fill_ring,
                comp_ring,
                rx_cons: 0,
                tx_prod: 0,
                fill_prod: 0,
                comp_cons: 0,
            };

            socket.populate_fill_ring();
            Ok(socket)
        }
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }

    pub fn is_hugepage(&self) -> bool {
        self.is_hugepage
    }

    fn populate_fill_ring(&mut self) {
        let prod = self.fill_prod;
        let ring_mask = self.fill_ring.mask;
        let raw_ring = self.fill_ring.descs as *mut u64;

        for i in 0..NUM_FRAMES {
            let addr = (i * FRAME_SIZE) as u64;
            unsafe {
                ptr::write_volatile(raw_ring.add(((prod + i as u32) & ring_mask) as usize), addr);
            }
        }
        self.fill_prod = prod + NUM_FRAMES as u32;
        fence(Ordering::Release);
        self.fill_ring.set_producer_index(self.fill_prod);
    }

    pub fn poll_read(&mut self, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        let t_acq = probes::stage_begin(StageId::RxRingAcquire);
        let rx_prod = self.rx_ring.producer_index();
        if self.rx_cons == rx_prod {
            probes::stage_end(StageId::RxRingAcquire, t_acq);
            return Ok(None);
        }

        fence(Ordering::Acquire);
        let rx_idx = self.rx_cons & self.rx_ring.mask;
        let rx_descs = self.rx_ring.descs as *const XdpDesc;
        let desc = unsafe { ptr::read_volatile(rx_descs.add(rx_idx as usize)) };
        probes::stage_end(StageId::RxRingAcquire, t_acq);

        let t_copy = probes::stage_begin(StageId::PayloadCopy);
        let umem_packet_ptr = unsafe { self.umem_area.add(desc.addr as usize) };
        let len = desc.len as usize;
        let copy_len = len.min(buf.len());
        unsafe {
            ptr::copy_nonoverlapping(umem_packet_ptr, buf.as_mut_ptr(), copy_len);
        }
        probes::stage_end(StageId::PayloadCopy, t_copy);

        let fill_idx = self.fill_prod & self.fill_ring.mask;
        let fill_descs = self.fill_ring.descs as *mut u64;
        unsafe {
            ptr::write_volatile(fill_descs.add(fill_idx as usize), desc.addr & !(FRAME_SIZE as u64 - 1));
        }

        self.fill_prod += 1;
        self.rx_cons += 1;

        fence(Ordering::Release);
        self.rx_ring.set_consumer_index(self.rx_cons);
        self.fill_ring.set_producer_index(self.fill_prod);

        Ok(Some(copy_len))
    }

    #[inline(always)]
    pub fn poll_read_batch(&mut self, out_packets: &mut [Vec<u8>]) -> usize {
        let rx_prod = self.rx_ring.producer_index();
        let available = rx_prod.wrapping_sub(self.rx_cons) as usize;
        if available == 0 {
            return 0;
        }

        fence(Ordering::Acquire);
        let batch_count = available.min(out_packets.len()).min(BATCH_SIZE);
        let rx_descs = self.rx_ring.descs as *const XdpDesc;
        let fill_descs = self.fill_ring.descs as *mut u64;

        for i in 0..batch_count {
            let rx_idx = (self.rx_cons + i as u32) & self.rx_ring.mask;
            let desc = unsafe { ptr::read_volatile(rx_descs.add(rx_idx as usize)) };
            let len = desc.len as usize;

            let umem_packet_ptr = unsafe { self.umem_area.add(desc.addr as usize) };
            let target_vec = &mut out_packets[i];
            target_vec.resize(len, 0);
            unsafe {
                ptr::copy_nonoverlapping(umem_packet_ptr, target_vec.as_mut_ptr(), len);
            }

            let fill_idx = (self.fill_prod + i as u32) & self.fill_ring.mask;
            unsafe {
                ptr::write_volatile(fill_descs.add(fill_idx as usize), desc.addr & !(FRAME_SIZE as u64 - 1));
            }
        }

        self.rx_cons += batch_count as u32;
        self.fill_prod += batch_count as u32;

        fence(Ordering::Release);
        self.rx_ring.set_consumer_index(self.rx_cons);
        self.fill_ring.set_producer_index(self.fill_prod);

        batch_count
    }

    pub fn write_async(&mut self, buf: &[u8]) -> std::io::Result<Option<usize>> {
        self.reclaim_completions();
        let t_tx = probes::stage_begin(StageId::TxEnqueue);

        let tx_cons = self.tx_ring.consumer_index();
        if self.tx_prod - tx_cons >= self.tx_ring.size {
            probes::stage_end(StageId::TxEnqueue, t_tx);
            return Ok(None);
        }

        let frame_index = (self.tx_prod & self.tx_ring.mask) as usize;
        let tx_addr = (frame_index * FRAME_SIZE) as u64;

        let umem_packet_ptr = unsafe { self.umem_area.add(tx_addr as usize) };
        unsafe {
            ptr::copy_nonoverlapping(buf.as_ptr(), umem_packet_ptr, buf.len());
        }

        let tx_descs = self.tx_ring.descs as *mut XdpDesc;
        let desc = XdpDesc {
            addr: tx_addr,
            len: buf.len() as u32,
            options: 0,
        };

        unsafe {
            ptr::write_volatile(tx_descs.add(frame_index), desc);
        }

        self.tx_prod += 1;
        fence(Ordering::Release);
        self.tx_ring.set_producer_index(self.tx_prod);

        unsafe {
            libc::send(self.fd, ptr::null(), 0, libc::MSG_DONTWAIT);
        }

        probes::stage_end(StageId::TxEnqueue, t_tx);
        Ok(Some(buf.len()))
    }

    fn reclaim_completions(&mut self) {
        let t_reap = probes::stage_begin(StageId::TxCompleteReap);
        let comp_prod = self.comp_ring.producer_index();
        if self.comp_cons == comp_prod {
            probes::stage_end(StageId::TxCompleteReap, t_reap);
            return;
        }
        fence(Ordering::Acquire);
        self.comp_cons = comp_prod;
        self.comp_ring.set_consumer_index(self.comp_cons);
        probes::stage_end(StageId::TxCompleteReap, t_reap);
    }
}

impl Drop for XdpSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
            if self.is_hugepage {
                libc::munmap(self.umem_area as *mut libc::c_void, UMEM_SIZE);
            } else {
                libc::free(self.umem_area as *mut libc::c_void);
            }
        }
    }
}
