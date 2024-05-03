use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use nom::Err;
use nom::error::{ErrorKind, make_error, VerboseError};
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::{IResult, Parser};
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::combinator::into;
use nom::multi::{count, length_data, length_value, many_till};
use nom::sequence::Tuple;

type MessageParseError<I> = VerboseError<I>;
const OFFSET_TAG: u16 = 0b1100000000000000;

#[derive(Debug, PartialEq)]
pub(crate) struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
    phantom: PhantomData<()>
}
impl DnsMessage {
    pub fn make(header_main: DnsHeaderMain, questions: Vec<DnsQuestion>, answers: Vec<DnsAnswer>) -> Self {
        let header = DnsHeader {
            id: header_main.id,
            bits1: header_main.bits1,
            bits2: header_main.bits2,
            question_count: questions.len().try_into().unwrap(),
            answer_count: answers.len().try_into().unwrap(),
            authority_count: 0,
            additional_count: 0,
            phantom: Default::default(),
        };
        Self {header, questions, answers, phantom: Default::default()}
    }
    pub fn write_into<W: Write + Seek>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let mut compression_offsets = HashMap::new();
        self.header.write_into(writer)?;
        for question in &self.questions {
            question.write_into(writer, &mut compression_offsets)?;
        }
        for answer in &self.answers {
            answer.write_into(writer, &mut compression_offsets)?;
        }
        Ok(())
    }
    pub fn write_into_cursor_buf<'a, const N: usize>(&self, buf: &'a mut Cursor<[u8; N]>) -> &'a [u8] {
        buf.seek(SeekFrom::Start(0)).unwrap();
        self.write_into(buf).unwrap();
        buf.flush().unwrap();
        &buf.get_ref()[..buf.position() as usize]
    }
    pub fn parse(message: &[u8]) -> IResult<&[u8], Self, MessageParseError<&[u8]>> {
        let (bytes, header) = DnsHeader::parse(message)?;
        let (bytes, (questions, answers)) =
            (count(DnsQuestion::parse(message), header.question_count as usize), count(DnsAnswer::parse(message), header.answer_count as usize)).parse(bytes)?;
        let message = Self{header, questions, answers, phantom: Default::default()};
        Ok((bytes, message))
    }
}

#[derive(Debug)]
pub(crate) struct DnsHeaderMain {
    /// A random ID assigned to query packets. Response packets must reply with the same ID.
    pub id: u16,
    pub bits1: DnsHeaderBits1,
    pub bits2: DnsHeaderBits2,
}

#[derive(Debug, PartialEq)]
pub(crate) struct DnsHeader {
    /// A random ID assigned to query packets. Response packets must reply with the same ID.
    pub id: u16,
    pub bits1: DnsHeaderBits1,
    pub bits2: DnsHeaderBits2,
    /// Number of questions in the Question section.
    pub question_count: u16,
    /// Number of records in the Answer section.
    pub answer_count: u16,
    /// Number of records in the Authority section.
    pub authority_count: u16,
    /// Number of records in the Additional section.
    pub additional_count: u16,
    phantom: PhantomData<()>,
}
impl DnsHeader {
    fn write_into(&self, writer: &mut impl Write) -> Result<(), std::io::Error> {
        writer.write_all(&self.id.to_be_bytes())?;
        writer.write_all(&[self.bits1.into(), self.bits2.into()])?;
        writer.write_all(&self.question_count.to_be_bytes())?;
        writer.write_all(&self.answer_count.to_be_bytes())?;
        writer.write_all(&self.authority_count.to_be_bytes())?;
        writer.write_all(&self.additional_count.to_be_bytes())?;
        Ok(())
    }
    fn parse(bytes: &[u8]) -> IResult<&[u8], Self, MessageParseError<&[u8]>> {
        let (bytes, (id, bits1, bits2, question_count, answer_count, authority_count, additional_count))
            = (be_u16, parser_try_into(be_u8), parser_try_into(be_u8), be_u16, be_u16, be_u16, be_u16).parse(bytes)?;
        let header = Self{
            id,
            bits1,
            bits2,
            question_count,
            answer_count,
            authority_count,
            additional_count,
            phantom: Default::default(),
        };
        Ok((bytes, header))
    }
}
#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) struct DnsHeaderBits1 {
    /// 1 bit   Query/Response Indicator (QR)   1 for a reply packet, 0 for a question packet.
    pub is_response: bool,
    /// 4 bits  Operation Code (OPCODE)         Specifies the kind of query in a message.
    pub opcode: DnsHeaderOpcode,
    /// 1 bit   Authoritative Answer (AA)       1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    pub is_authoritative: bool,
    /// 1 bit   Truncation (TC)                 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    pub is_truncated: bool,
    /// 1 bit   Recursion Desired (RD)          Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    pub is_recursion_desired: bool,
}
impl TryFrom<u8> for DnsHeaderBits1 {
    type Error = ConversionError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let res = Self {
            is_response: (value & 0b10000000) > 0,
            opcode: ((value & 0b01111000) >> 3).try_into()?,
            is_authoritative: (value & 0b00000100) > 0,
            is_truncated: (value & 0b00000010) > 0,
            is_recursion_desired: (value & 0b00000001) > 0,
        };
        Ok(res)
    }
}
impl Into<u8> for DnsHeaderBits1 {
    fn into(self) -> u8 {
        let mut res = (self.opcode as u8) << 3;
        if self.is_response {
            res |= 0b10000000;
        }
        if self.is_authoritative {
            res |= 0b00000100;
        }
        if self.is_truncated {
            res |= 0b00000010;
        }
        if self.is_recursion_desired {
            res |= 0b00000001;
        }
        res
    }
}
#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum DnsHeaderOpcode {
    Query = 0,
    InverseQuery = 1,
    Status = 2,
}
impl TryFrom<u8> for DnsHeaderOpcode {
    type Error = ConversionError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::Query as u8 => Ok(Self::Query),
            x if x == Self::InverseQuery as u8 => Ok(Self::InverseQuery),
            x if x == Self::Status as u8 => Ok(Self::Status),
            _ => Err(ConversionError),
        }
    }
}
#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) struct DnsHeaderBits2 {
    /// 1 bit   Recursion Available (RA)        Server sets this to 1 to indicate that recursion is available.
    pub is_recursion_available: bool,
    /// 3 bits  Reserved (Z)                    Used by DNSSEC queries. At inception, it was reserved for future use.
    /// 4 bits  Response Code (RCODE)           Response code indicating the status of the response.
    pub response_code: DnsHeaderResponseCode,
}
impl TryFrom<u8> for DnsHeaderBits2 {
    type Error = ConversionError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let res = Self {
            is_recursion_available: (value & 0b10000000) > 0,
            response_code: (value & 0b00001111).try_into()?,
        };
        Ok(res)
    }
}
impl Into<u8> for DnsHeaderBits2 {
    fn into(self) -> u8 {
        let mut res = self.response_code as u8;
        if self.is_recursion_available {
            res |= 0b10000000;
        }
        res
    }
}
#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum DnsHeaderResponseCode {
    NoError = 0,
    FormatError = 1,
    ServerFail = 2,
    /// Non-Existent Domain
    NXDomain = 3,
    NotImplemented = 4,
    Refused = 5,
    /// Name Exists when it should not
    YXDomain = 6,
    /// RR Set Exists when it should not
    YXRRSet = 7,
    /// RR Set that should exist does not
    NXRRSet = 8,
    /// Server Not Authoritative for zone or Not Authorized
    NotAuth = 9,
    /// Name not contained in zone
    NotZone = 10,
}
impl TryFrom<u8> for DnsHeaderResponseCode {
    type Error = ConversionError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::NoError as u8 => Ok(Self::NoError),
            x if x == Self::FormatError as u8 => Ok(Self::FormatError),
            x if x == Self::ServerFail as u8 => Ok(Self::ServerFail),
            x if x == Self::NXDomain as u8 => Ok(Self::NXDomain),
            x if x == Self::NotImplemented as u8 => Ok(Self::NotImplemented),
            x if x == Self::Refused as u8 => Ok(Self::Refused),
            x if x == Self::YXDomain as u8 => Ok(Self::YXDomain),
            x if x == Self::YXRRSet as u8 => Ok(Self::YXRRSet),
            x if x == Self::NXRRSet as u8 => Ok(Self::NXRRSet),
            x if x == Self::NotAuth as u8 => Ok(Self::NotAuth),
            x if x == Self::NotZone as u8 => Ok(Self::NotZone),
            _ => Err(ConversionError),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ConversionError;
impl Display for ConversionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("Conversion error")
    }
}
impl std::error::Error for ConversionError {}

#[derive(Debug, PartialEq)]
pub(crate) struct DnsQuestion {
    pub domain: String,
    pub question_type: DnsQuestionType,
    pub class: DnsQuestionClass,
}
impl DnsQuestion {
    fn write_into<'a, W: Write + Seek>(&'a self, writer: &mut W, compression_offsets: &mut HashMap<&'a str, u16>) -> Result<(), std::io::Error> {
        write_domain(&self.domain, writer, compression_offsets)?;
        writer.write_all(&(self.question_type as u16).to_be_bytes())?;
        writer.write_all(&(self.class as u16).to_be_bytes())?;
        Ok(())
    }
    fn parse<'a>(message: &'a [u8]) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Self, MessageParseError<&'a [u8]>> {
        |bytes| {
            let (bytes, (domain, question_type, class)) =
                (parse_domain(message, 0), parser_try_into(be_u16), parser_try_into(be_u16)).parse(bytes)?;
            let question = Self{domain, question_type, class};
            Ok((bytes, question))
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum DnsQuestionType {
    /// a host address
    A = 1,
    /// an authoritative name server
    NS = 2,
    /// the canonical name for an alias
    CNAME = 5,
    /// marks the start of a zone of authority
    SOA = 6,
    /// a well known service description
    WKS = 11,
    /// a domain name pointer
    PTR = 12,
    /// host information
    HINFO = 13,
    /// mailbox or mail list information
    MINFO = 14,
    /// mail exchange
    MX = 15,
    /// text strings
    TXT = 16,
}
impl TryFrom<u16> for DnsQuestionType {
    type Error = ConversionError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::A as u16 => Ok(Self::A),
            x if x == Self::NS as u16 => Ok(Self::NS),
            x if x == Self::CNAME as u16 => Ok(Self::CNAME),
            x if x == Self::SOA as u16 => Ok(Self::SOA),
            x if x == Self::WKS as u16 => Ok(Self::WKS),
            x if x == Self::PTR as u16 => Ok(Self::PTR),
            x if x == Self::HINFO as u16 => Ok(Self::HINFO),
            x if x == Self::MINFO as u16 => Ok(Self::MINFO),
            x if x == Self::MX as u16 => Ok(Self::MX),
            x if x == Self::TXT as u16 => Ok(Self::TXT),
            _ => Err(ConversionError),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum DnsQuestionClass {
    /// the Internet
    IN = 1,
    /// CHAOS
    CH = 3,
    /// Hesiod
    HS = 4,
}
impl TryFrom<u16> for DnsQuestionClass {
    type Error = ConversionError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::IN as u16 => Ok(Self::IN),
            x if x == Self::CH as u16 => Ok(Self::CH),
            x if x == Self::HS as u16 => Ok(Self::HS),
            _ => Err(ConversionError),
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct DnsAnswer {
    pub domain: String,
    pub question_type: DnsQuestionType,
    pub class: DnsQuestionClass,
    /// The duration in seconds a record can be cached before requerying
    pub time_to_live: u32,
    /// Data specific to the record type
    pub record_data: Vec<u8>,
}
impl DnsAnswer {
    fn write_into<'a, W: Write + Seek>(&'a self, writer: &mut W, compression_offsets: &mut HashMap<&'a str, u16>) -> Result<(), std::io::Error> {
        write_domain(&self.domain, writer, compression_offsets)?;
        writer.write_all(&(self.question_type as u16).to_be_bytes())?;
        writer.write_all(&(self.class as u16).to_be_bytes())?;
        writer.write_all(&self.time_to_live.to_be_bytes())?;
        writer.write_all(&(self.record_data.len() as u16).to_be_bytes())?;
        if self.record_data.len() > 0 {
            writer.write_all(&self.record_data)?;
        }
        Ok(())
    }
    fn parse<'a>(message: &'a [u8]) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Self, MessageParseError<&'a [u8]>> {
        |bytes| {
            let (bytes, (domain, question_type, class, time_to_live, record_data)) =
                (parse_domain(message, 0), parser_try_into(be_u16), parser_try_into(be_u16), be_u32, length_data(be_u16)).parse(bytes)?;
            let record_data = record_data.to_vec();
            let question = Self{domain, question_type, class, time_to_live, record_data};
            Ok((bytes, question))
        }
    }
}

fn parser_try_into<I, F, O1, O2>(mut parser: F) -> impl FnMut(I) -> IResult<I, O2, MessageParseError<I>>
where
    I: Copy,
    F: Parser<I, O1, MessageParseError<I>>,
    O1: TryInto<O2>,
{
    move |input: I| {
        let (tail, result) = parser.parse(input)?;
        let Ok(res)= result.try_into() else {
            return Err(Err::Error(make_error(input, ErrorKind::Verify)));
        };
        Ok((tail, res))
    }
}

fn parser_none<I, O, E, F: Parser<I, O, E>, S>(mut parser: F) -> impl FnMut(I) -> IResult<I, Option<S>, E> {
    move |input: I| {
        let (tail, _result) = parser.parse(input)?;
        Ok((tail, None))
    }
}

fn parse_string(bytes: &[u8]) -> IResult<&[u8], &str, MessageParseError<&[u8]>> {
    match std::str::from_utf8(bytes) {
        Ok(x) => Ok((&[], x)),
        Err(_) => Err(Err::Error(make_error(bytes, ErrorKind::Verify))),
    }
}

fn parse_domain<'a>(message: &'a [u8], recursion_level: u8) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], String, MessageParseError<&'a [u8]>> {
    move |input| {
        // i could also add a size limit to make sure that the string is not too lar, but we are already limited by the initial buffer size, so it's ok
        let (tail, (mut domain_parts, offset)) = many_till(
            length_value(be_u8, parse_string),
            alt((parser_none(tag(b"\0")), into(parse_offset)))
        ).parse(input)?;

        let decompressed = if let Some(offset) = offset {
            if recursion_level > 5 {
                return Err(Err::Error(make_error(input, ErrorKind::Verify)));
            }
            let offset = offset as usize;
            let (_, decompressed) = parse_domain(message, recursion_level + 1)(&message[offset..])?;
            Some(decompressed)
        } else {
            None
        };
        if let Some(decompressed) = &decompressed {
            domain_parts.push(decompressed);
        }
        if domain_parts.len() == 0 {
            return Err(Err::Error(make_error(input, ErrorKind::Verify)));
        }
        let domain = domain_parts.join(".");
        Ok((tail, domain))
    }
}

fn parse_offset(input: &[u8]) -> IResult<&[u8], u16, MessageParseError<&[u8]>> {
    let (tail, offset) = be_u16(input)?;
    if (offset & OFFSET_TAG) != OFFSET_TAG {
        return Err(Err::Error(make_error(input, ErrorKind::Verify)));
    }
    let offset = offset & !OFFSET_TAG;
    Ok((tail, offset))
}

fn write_domain<'a, W: Write + Seek>(domain: &'a str, writer: &mut W, compression_offsets: &mut HashMap<&'a str, u16>) -> Result<(), std::io::Error> {
    let mut domain_tail = domain;
    loop {
        match compression_offsets.get(domain_tail) {
            Some(offset) => {
                let offset = offset | OFFSET_TAG; 
                writer.write_all(&offset.to_be_bytes())?;
                break;
            }
            None => {
                let current_offset = writer.stream_position().unwrap() as u16;
                compression_offsets.insert(domain_tail, current_offset);
                
                let (domain_part, next_tail) = match domain_tail.split_once('.') {
                    Some(x) => (x.0, Some(x.1)),
                    None => (domain_tail, None),
                };
                writer.write_all(&(domain_part.len() as u8).to_be_bytes())?;
                writer.write_all(domain_part.as_bytes())?;
                match next_tail {
                    Some(tail) => domain_tail = tail,
                    None => {
                        writer.write_all(&[0])?;
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use std::io::Cursor;
    use std::net::Ipv4Addr;
    use super::*;
    #[test]
    fn test_write_and_parse() {
        let mut buf = Cursor::new([0u8; 2048]);

        let response_ip_int: u32 = Ipv4Addr::new(8, 8, 8, 8).into();
        let orig = DnsMessage::make(
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
            vec![
                DnsAnswer {
                    domain: "codecrafters.io".to_string(),
                    question_type: DnsQuestionType::A,
                    class: DnsQuestionClass::IN,
                    time_to_live: 60,
                    record_data: response_ip_int.to_be_bytes().to_vec(),
                }
            ],
        );
        let write_data = orig.write_into_cursor_buf(&mut buf);

        let (tail, parsed) = match DnsMessage::parse(write_data) {
            Ok(x) => x,
            Err(err) => panic!("{err:?}"),
        };
        assert_eq!(orig, parsed);
        assert_eq!(0, tail.len());
    }
}