use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

const SOCKET_BUF_SIZE: usize = 64 * 1024;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);

pub fn configure_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock = SockRef::from(stream);
    let _ = sock.set_recv_buffer_size(SOCKET_BUF_SIZE);
    let _ = sock.set_send_buffer_size(SOCKET_BUF_SIZE);
    let ka = TcpKeepalive::new()
        .with_time(KEEPALIVE_INTERVAL)
        .with_interval(KEEPALIVE_INTERVAL);
    let _ = sock.set_tcp_keepalive(&ka);
}

pub fn build_reuseport_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}
