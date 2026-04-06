use socket2::{SockRef, TcpKeepalive};
use std::time::Duration;
use tokio::net::TcpStream;

const SOCKET_BUF_SIZE: usize = 256 * 1024;
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
