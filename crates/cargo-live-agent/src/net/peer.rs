//! Which process opened a connection to the build proxy.
//!
//! The proxy accepts connections only from the build step's own processes:
//! the step's Cargo process and its descendants. On Linux the accepted
//! loopback connection's peer address is mapped to its socket inode through
//! `/proc/net/tcp` and `/proc/net/tcp6`, the inode to the processes holding
//! it through `/proc/<pid>/fd`, and each of those processes must reach the
//! step's Cargo process by following `PPid` in `/proc/<pid>/status`.
//! Anything that cannot be resolved is refused. Nothing is cached between
//! connections.
//!
//! This narrows who can use the proxy password to the job's own process
//! tree; it does not separate jobs of the same OS user from each other
//! (such a process can still ptrace or read `/proc` of the job's
//! processes).

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

/// The pid of a build step's Cargo process, set once it is spawned.
pub type JobRoot = Arc<OnceLock<u32>>;

/// Checks that the connection from `peer` to the proxy's `local` address
/// was opened by a process of the job rooted at `root`. Blocking (reads
/// `/proc`); `Err` says why not.
#[cfg(target_os = "linux")]
pub fn check(peer: SocketAddr, local: SocketAddr, root: Option<u32>) -> Result<(), String> {
    linux::check(peer, local, root)
}

/// Not checked on other systems (the agent runs on Linux).
#[cfg(not(target_os = "linux"))]
pub fn check(_peer: SocketAddr, _local: SocketAddr, _root: Option<u32>) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::path::Path;

    /// Ancestors followed at most (guards against odd `/proc` states).
    const MAX_DEPTH: usize = 4096;

    pub fn check(peer: SocketAddr, local: SocketAddr, root: Option<u32>) -> Result<(), String> {
        let root = root.ok_or("the build step has not started")?;
        let inode = socket_inode(Path::new("/proc"), peer, local)?;
        let owners = socket_owners(Path::new("/proc"), inode)?;
        if owners.is_empty() {
            return Err(format!("no process holds the connection from {peer}"));
        }
        for pid in owners {
            if !descends_from(Path::new("/proc"), pid, root) {
                return Err(format!("process {pid} is not part of this build"));
            }
        }
        Ok(())
    }

    /// The inode of the socket bound to `peer` and connected to `local`.
    pub(super) fn socket_inode(
        proc: &Path,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Result<u64, String> {
        let mut readable = false;
        for table in ["net/tcp", "net/tcp6"] {
            let Ok(text) = fs::read_to_string(proc.join(table)) else {
                continue;
            };
            readable = true;
            if let Some(inode) = find_inode(&text, peer, local) {
                return Ok(inode);
            }
        }
        Err(if readable {
            format!("connection from {peer} not found in /proc/net/tcp")
        } else {
            "cannot read /proc/net/tcp".to_owned()
        })
    }

    /// Searches a `/proc/net/tcp{,6}` table for a socket whose local
    /// address is `peer` and remote address is `local`.
    pub(super) fn find_inode(table: &str, peer: SocketAddr, local: SocketAddr) -> Option<u64> {
        let canonical = |a: SocketAddr| (a.ip().to_canonical(), a.port());
        let (peer, local) = (canonical(peer), canonical(local));
        table.lines().skip(1).find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (src, dst, inode) = (fields.get(1)?, fields.get(2)?, fields.get(9)?);
            let inode: u64 = inode.parse().ok()?;
            (inode != 0 && parse_addr(src)? == peer && parse_addr(dst)? == local).then_some(inode)
        })
    }

    /// `0100007F:1F90` (IPv4) or 32 hex digits and a port (IPv6). The
    /// kernel prints each 32-bit word of the address as a native-endian
    /// number and the port in host order.
    pub(super) fn parse_addr(field: &str) -> Option<(IpAddr, u16)> {
        let (addr, port) = field.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        let mut bytes = Vec::with_capacity(16);
        if addr.len() % 8 != 0 {
            return None;
        }
        for i in (0..addr.len()).step_by(8) {
            let word = u32::from_str_radix(addr.get(i..i + 8)?, 16).ok()?;
            bytes.extend_from_slice(&word.to_ne_bytes());
        }
        let ip = match bytes.len() {
            4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?)),
            16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?)),
            _ => return None,
        };
        Some((ip.to_canonical(), port))
    }

    /// Every process with a file descriptor for socket `inode`. Processes
    /// that cannot be inspected (other users, exited) are skipped; they
    /// cannot hold this user's connection without this user's help.
    pub(super) fn socket_owners(proc: &Path, inode: u64) -> Result<Vec<u32>, String> {
        let target = format!("socket:[{inode}]");
        let entries = fs::read_dir(proc).map_err(|e| format!("cannot read /proc: {e}"))?;
        let mut owners = Vec::new();
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
                continue;
            };
            if fds
                .flatten()
                .any(|fd| fs::read_link(fd.path()).is_ok_and(|l| l.as_os_str() == target.as_str()))
            {
                owners.push(pid);
            }
        }
        Ok(owners)
    }

    fn parent(proc: &Path, pid: u32) -> Option<u32> {
        let status = fs::read_to_string(proc.join(pid.to_string()).join("status")).ok()?;
        status
            .lines()
            .find_map(|l| l.strip_prefix("PPid:"))
            .and_then(|p| p.trim().parse().ok())
    }

    /// Whether `pid` is `root` or one of its descendants.
    pub(super) fn descends_from(proc: &Path, mut pid: u32, root: u32) -> bool {
        for _ in 0..MAX_DEPTH {
            if pid == root {
                return true;
            }
            if pid <= 1 {
                return false;
            }
            match parent(proc, pid) {
                Some(p) => pid = p,
                None => return false,
            }
        }
        false
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::linux::{descends_from, find_inode, parse_addr, socket_inode, socket_owners};
    use super::*;
    use std::path::Path;

    #[test]
    fn parses_proc_net_tcp() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
           0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1 0000000000000000 100 0 0 10 0\n\
           1: 0100007F:A2B4 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 222 1 0000000000000000 20 4 30 10 -1\n\
           2: 0100007F:1F90 0100007F:A2B4 01 00000000:00000000 00:00000000 00000000  1000        0 333 1 0000000000000000 20 4 30 10 -1\n";
        let peer: SocketAddr = "127.0.0.1:41652".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(find_inode(table, peer, local), Some(222));
        assert_eq!(find_inode(table, local, peer), Some(333));
        assert_eq!(
            find_inode(table, "127.0.0.1:1".parse().unwrap(), local),
            None
        );
        let v6 = "  sl  local_address                         remote_address                        st\n\
           0: 0000000000000000FFFF00000100007F:A2B4 0000000000000000FFFF00000100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 444 1\n\
           1: 00000000000000000000000001000000:0016 00000000000000000000000001000000:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 555 1\n";
        // IPv4-mapped addresses match their IPv4 form.
        assert_eq!(find_inode(v6, peer, local), Some(444));
        assert_eq!(
            find_inode(
                v6,
                "[::1]:22".parse().unwrap(),
                "[::1]:40000".parse().unwrap()
            ),
            Some(555)
        );
        assert_eq!(
            parse_addr("0100007F:0050"),
            Some(("127.0.0.1".parse().unwrap(), 80))
        );
        assert_eq!(parse_addr("zz"), None);
        assert_eq!(parse_addr("0100007:0050"), None);
    }

    #[test]
    fn finds_this_process_and_its_ancestry() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(local).unwrap();
        let (_server, peer) = listener.accept().unwrap();
        assert_eq!(client.local_addr().unwrap(), peer);
        let proc = Path::new("/proc");
        let inode = socket_inode(proc, peer, local).unwrap();
        assert_eq!(socket_owners(proc, inode).unwrap(), [std::process::id()]);
        let me = std::process::id();
        assert!(check(peer, local, Some(me)).is_ok());
        // The parent of the test process is not part of a job rooted here.
        let parent = std::os::unix::process::parent_id();
        assert!(descends_from(proc, me, parent));
        let err = check(peer, local, Some(parent + 1_000_000)).unwrap_err();
        assert!(err.contains("is not part of this build"), "{err}");
        assert!(check(peer, local, None).is_err());
        drop(client);
        // Unknown connections are refused.
        assert!(check("127.0.0.1:1".parse().unwrap(), local, Some(me)).is_err());
    }
}
