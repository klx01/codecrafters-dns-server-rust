use std::io::{Cursor, Seek, SeekFrom, Write};
use std::net::UdpSocket;
use crate::message::*;

mod message;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053")
        .expect("Failed to bind to address");

    let mut buf = Cursor::new([0u8; 2048]);

    loop {
        let (read_size, source) = match udp_socket.recv_from(buf.get_mut()) {
            Ok(x) => x,
            Err(err) => {
                eprintln!("error reading from socket {err}");
                continue;
            }
        };

        let read_data = &buf.get_ref()[..read_size];
        match DnsMessage::parse(read_data) {
            Ok((tail, message)) => println!("got request {message:?}, tail: {tail:?}"),
            Err(error) => eprintln!("failed to parse message {error:?}"),
        }

        let response = DnsMessage::make(
            DnsHeaderMain {
                id: 1234,
                bits1: DnsHeaderBits1 {
                    is_response: true,
                    opcode: DnsHeaderOpcode::Query,
                    is_authoritative: false,
                    is_truncated: false,
                    is_recursion_desired: false,
                },
                bits2: DnsHeaderBits2 {
                    is_recursion_available: false,
                    response_code: DnsHeaderResponseCode::NoError,
                },
            },
            vec![
                DnsQuestion {
                    domain: "codecrafters.io".to_string(),
                    question_type: DnsQuestionType::A,
                    class: DnsQuestionClass::IN,
                }
            ],
        );
        buf.seek(SeekFrom::Start(0)).unwrap();
        response.write_into(&mut buf).unwrap();
        buf.flush().unwrap();
        let write_data = &buf.get_ref()[..buf.position() as usize];

        let send_result = udp_socket.send_to(write_data, source);
        match send_result {
            Ok(_) => {}
            Err(err) => eprintln!("failed to send response {err}")
        }
    }
}
