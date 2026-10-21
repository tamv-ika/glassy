//! AF_XDP bind probes with raw syscalls, so the probe needs no libxdp on the host.
//! Constants and layouts follow <linux/if_xdp.h>.

use std::ffi::CString;
use std::io;
use std::mem::size_of;
use std::thread::sleep;
use std::time::Duration;

use crate::Probe;

const AF_XDP: libc::c_int = 44;
const SOL_XDP: libc::c_int = 283;
const XDP_RX_RING: libc::c_int = 2;
const XDP_UMEM_REG: libc::c_int = 4;
const XDP_UMEM_FILL_RING: libc::c_int = 5;
const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;
pub const XDP_COPY: u16 = 1 << 1;
pub const XDP_ZEROCOPY: u16 = 1 << 2;

const FRAME_COUNT: usize = 4096;
const FRAME_SIZE: u32 = 2048;
const RING_SIZE: libc::c_int = 2048;
// The kernel frees a closed socket's queue asynchronously, so a bind right after an earlier
// probe on the same queue sees EBUSY for a short while.
const BUSY_RETRIES: u32 = 40;
const BUSY_BACKOFF: Duration = Duration::from_millis(50);

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    tx_metadata_len: u32,
}

#[repr(C)]
struct SockaddrXdp {
    family: u16,
    flags: u16,
    ifindex: u32,
    queue_id: u32,
    shared_umem_fd: u32,
}

/// Binds an AF_XDP socket to queue 0 of `iface` with `bind_flags` (`XDP_COPY` or `XDP_ZEROCOPY`).
pub fn probe(iface: &str, bind_flags: u16) -> Probe {
    let mut attempt = 0;
    loop {
        match try_bind(iface, bind_flags) {
            Ok(()) => return Probe::ok(),
            Err(e) if e.errno == Some(libc::EBUSY) && attempt < BUSY_RETRIES => {
                attempt += 1;
                sleep(BUSY_BACKOFF);
            }
            Err(e) => return Probe::failed(e.message),
        }
    }
}

struct SysError {
    message: String,
    errno: Option<i32>,
}

impl From<String> for SysError {
    fn from(message: String) -> Self {
        Self {
            message,
            errno: None,
        }
    }
}

fn try_bind(iface: &str, bind_flags: u16) -> Result<(), SysError> {
    let name = CString::new(iface).map_err(|e| e.to_string())?;
    // SAFETY: `name` is a valid NUL-terminated string.
    let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if ifindex == 0 {
        return Err(os_err("if_nametoindex").into());
    }
    // Declared before the socket so the socket closes first and releases the pinned pages.
    let umem = Umem::new(FRAME_COUNT * FRAME_SIZE as usize)?;
    // SAFETY: plain socket(2) call; the result is checked below.
    let sock = Fd(unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) });
    if sock.0 < 0 {
        return Err(os_err("socket").into());
    }
    let reg = XdpUmemReg {
        addr: umem.ptr as u64,
        len: umem.len as u64,
        chunk_size: FRAME_SIZE,
        headroom: 0,
        flags: 0,
        tx_metadata_len: 0,
    };
    setsockopt(sock.0, XDP_UMEM_REG, &reg, "XDP_UMEM_REG")?;
    setsockopt(sock.0, XDP_UMEM_FILL_RING, &RING_SIZE, "XDP_UMEM_FILL_RING")?;
    setsockopt(
        sock.0,
        XDP_UMEM_COMPLETION_RING,
        &RING_SIZE,
        "XDP_UMEM_COMPLETION_RING",
    )?;
    setsockopt(sock.0, XDP_RX_RING, &RING_SIZE, "XDP_RX_RING")?;
    let addr = SockaddrXdp {
        family: AF_XDP as u16,
        flags: bind_flags,
        ifindex,
        queue_id: 0,
        shared_umem_fd: 0,
    };
    // SAFETY: `addr` is a fully initialised sockaddr_xdp and the length matches it.
    let rc = unsafe {
        libc::bind(
            sock.0,
            (&raw const addr).cast::<libc::sockaddr>(),
            size_of::<SockaddrXdp>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        return Err(SysError {
            message: format!("bind: {err}"),
            errno: err.raw_os_error(),
        });
    }
    Ok(())
}

fn setsockopt<T>(fd: libc::c_int, opt: libc::c_int, value: &T, name: &str) -> Result<(), String> {
    // SAFETY: `value` points to a live `T` and the length passed is exactly its size.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            SOL_XDP,
            opt,
            (value as *const T).cast::<libc::c_void>(),
            size_of::<T>() as libc::socklen_t,
        )
    };
    if rc != 0 { Err(os_err(name)) } else { Ok(()) }
}

fn os_err(what: &str) -> String {
    format!("{what}: {}", io::Error::last_os_error())
}

struct Fd(libc::c_int);

impl Drop for Fd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: the descriptor is owned by this guard and closed exactly once.
            unsafe { libc::close(self.0) };
        }
    }
}

/// Anonymous page-aligned memory for the UMEM frames.
struct Umem {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Umem {
    fn new(len: usize) -> Result<Self, String> {
        // SAFETY: anonymous private mapping with no address hint; checked for MAP_FAILED.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(os_err("mmap"));
        }
        Ok(Self { ptr, len })
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`len` describe a mapping created in `new` and unmapped only here.
        unsafe { libc::munmap(self.ptr, self.len) };
    }
}
