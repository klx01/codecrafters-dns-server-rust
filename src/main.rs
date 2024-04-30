use std::net::UdpSocket;
use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053")
        .context("Failed to bind to address")?;
    
    let mut buf = [0; 512];
    
    loop {
        let (size, source) = udp_socket.recv_from(&mut buf)
            .context("failed to read from socket")?;
        let data = &buf[..size];
        println!("Received {size} bytes from {source} {data:?}");
        udp_socket.send_to(data, source)
            .context("Failed to send response")?;
    }
}
