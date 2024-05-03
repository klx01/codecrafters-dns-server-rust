use std::io::Cursor;
use std::net::{Ipv4Addr, UdpSocket};
use crate::message::*;

mod message;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053")
        .expect("Failed to bind to address");

    let mut buf = Cursor::new([0u8; 2048]);

    'outer: loop {
        let (read_size, source) = match udp_socket.recv_from(buf.get_mut()) {
            Ok(x) => x,
            Err(err) => {
                eprintln!("error reading from socket {err}");
                continue;
            }
        };

        let read_data = &buf.get_ref()[..read_size];
        let request = match DnsMessage::parse(read_data) {
            Ok((_tail, message)) => { 
                //println!("got request {message:?}, tail: {_tail:?}");
                message
            },
            Err(error) => { 
                eprintln!("failed to parse message {error:?}");
                continue;
            },
        };

        let response_code = if request.header.bits1.opcode == DnsHeaderOpcode::Query { 
            DnsHeaderResponseCode::NoError 
        } else {
            DnsHeaderResponseCode::NotImplemented
        };
        let response_ip_int: u32 = Ipv4Addr::new(8, 8, 8, 8).into();
        let mut answers = vec![];
        for question in &request.questions {
            if question.question_type != DnsQuestionType::A {
                eprintln!("Got a question type {:?}, can not respond", question.question_type);
                continue 'outer;
            }
            if question.class != DnsQuestionClass::IN {
                eprintln!("Got a question class {:?}, can not respond", question.class);
                continue 'outer;
            }
            answers.push(
                DnsAnswer {
                    domain: question.domain.clone(),
                    question_type: question.question_type,
                    class: question.class,
                    time_to_live: 60,
                    record_data: response_ip_int.to_be_bytes().to_vec(),
                }
            );
        }
        let response = DnsMessage::make(
            DnsHeaderMain {
                id: request.header.id,
                bits1: DnsHeaderBits1 {
                    is_response: true,
                    opcode: request.header.bits1.opcode,
                    is_authoritative: false,
                    is_truncated: false,
                    is_recursion_desired: request.header.bits1.is_recursion_desired,
                },
                bits2: DnsHeaderBits2 {
                    is_recursion_available: false,
                    response_code,
                },
            },
            request.questions,
            answers,
        );
        let write_data = response.write_into_cursor_buf(&mut buf);

        let send_result = udp_socket.send_to(write_data, source);
        match send_result {
            Ok(_) => {}
            Err(err) => eprintln!("failed to send response {err}")
        }
    }
}
