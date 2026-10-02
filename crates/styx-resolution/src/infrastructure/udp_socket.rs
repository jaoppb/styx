//! Binding a group of UDP sockets that share one listen address.
//!
//! On Linux every socket in the group sets `SO_REUSEPORT`, so the kernel spreads
//! incoming datagrams across one receive loop per socket. Every other target binds
//! exactly one socket: `SO_REUSEPORT` balances unicast datagrams only on Linux.

use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;

use tokio::net::UdpSocket;

/// The UDP socket count per address for this host.
///
/// One per available core on Linux, falling back to one when the count cannot be
/// read; always one elsewhere.
#[must_use]
pub fn default_socket_count() -> NonZeroUsize {
    if cfg!(target_os = "linux") {
        std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN)
    } else {
        NonZeroUsize::MIN
    }
}

/// Binds `count` sockets to `addr`, all sharing one port.
///
/// The first socket binds `addr` as given; the rest bind the port the OS assigned to
/// the first, so a port-0 bind yields a single shared port.
///
/// # Errors
/// Returns the [`io::Error`] of the first socket that fails to be created or bound.
#[cfg(target_os = "linux")]
pub async fn bind_reuseport_group(
    addr: SocketAddr,
    count: NonZeroUsize,
) -> io::Result<Vec<UdpSocket>> {
    let first = bind_reuseport(addr)?;
    let mut shared = addr;
    shared.set_port(first.local_addr()?.port());

    let mut sockets = Vec::with_capacity(count.get());
    sockets.push(first);
    for _ in 1..count.get() {
        sockets.push(bind_reuseport(shared)?);
    }
    Ok(sockets)
}

/// Binds a single socket to `addr`; `count` above one is logged and ignored.
///
/// # Errors
/// Returns the [`io::Error`] if the socket cannot be bound.
#[cfg(not(target_os = "linux"))]
pub async fn bind_reuseport_group(
    addr: SocketAddr,
    count: NonZeroUsize,
) -> io::Result<Vec<UdpSocket>> {
    if count > NonZeroUsize::MIN {
        tracing::info!(
            %addr,
            requested = count.get(),
            "SO_REUSEPORT load balancing is Linux-only; binding one UDP socket"
        );
    }
    Ok(vec![UdpSocket::bind(addr).await?])
}

#[cfg(target_os = "linux")]
fn bind_reuseport(addr: SocketAddr) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn port_zero_group_shares_one_port() {
        let four = NonZeroUsize::new(4).unwrap();
        let sockets = bind_reuseport_group(SocketAddr::from(([127, 0, 0, 1], 0)), four)
            .await
            .unwrap();
        assert_eq!(sockets.len(), 4);
        let port = sockets[0].local_addr().unwrap().port();
        assert_ne!(port, 0);
        for socket in &sockets {
            assert_eq!(socket.local_addr().unwrap().port(), port);
        }
    }

    #[tokio::test]
    async fn a_single_socket_group_binds_once() {
        let sockets =
            bind_reuseport_group(SocketAddr::from(([127, 0, 0, 1], 0)), NonZeroUsize::MIN)
                .await
                .unwrap();
        assert_eq!(sockets.len(), 1);
    }
}
