use std::net::UdpSocket;
use std::{mem, slice};
use crate::message::{DnsHeader, DnsHeaderBits1, DnsHeaderBits2, DnsHeaderOpcode, DnsHeaderRaw, DnsHeaderResponseCode};

mod message;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053")
        .expect("Failed to bind to address");

    let mut header_raw = DnsHeaderRaw::default();
    let response_header = DnsHeader {
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
        question_count: 0,
        answer_count: 0,
        authority_count: 0,
        additional_count: 0,
    };
    let response_header = response_header.get_raw();
    let response_bytes = unsafe{ get_bytes_ref_of_struct(&response_header) };

    loop {
        let header_bytes = unsafe { get_bytes_ref_of_struct_mut(&mut header_raw) };
        let (read_size, source) = match udp_socket.recv_from(header_bytes) {
            Ok(x) => x,
            Err(err) => {
                eprintln!("error reading from socket {err}");
                continue;
            }
        };

        let send_result = udp_socket.send_to(response_bytes, source);
        match send_result {
            Ok(_) => {}
            Err(err) => eprintln!("failed to send response {err}")
        }

        if read_size != header_bytes.len() {
            eprintln!("not enough bytes for the header: read {read_size}, expected {}", header_bytes.len());
            continue;
        }
        drop(header_bytes);

        let header_data = match header_raw.parse() {
            Ok(x) => x,
            Err(err) => {
                eprintln!("failed to parse header {err}");
                continue;
            }
        };
        println!("got request header {header_data:?}");
    }
}


unsafe fn get_bytes_ref_of_struct_mut<T: Sized>(struct_ref: &mut T) -> &mut [u8] {
    slice::from_raw_parts_mut(
        struct_ref as *mut T as *mut u8,
        mem::size_of::<T>()
    )
}
unsafe fn get_bytes_ref_of_struct<T: Sized>(struct_ref: &T) -> &[u8] {
    slice::from_raw_parts(
        struct_ref as *const T as *const u8,
        mem::size_of::<T>()
    )
}