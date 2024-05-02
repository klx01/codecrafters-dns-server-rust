use std::fmt::{Display, Formatter};
use std::io::Write;
use nom::Err::Error;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u16, be_u8};
use nom::sequence::Tuple;

#[derive(Debug)]
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
}
impl DnsHeader {
    pub fn write_into(&self, writer: &mut impl Write) -> Result<usize, std::io::Error> {
        writer.write_all(&self.id.to_be_bytes())?;
        writer.write_all(&[self.bits1.into(), self.bits2.into()])?;
        writer.write_all(&self.question_count.to_be_bytes())?;
        writer.write_all(&self.answer_count.to_be_bytes())?;
        writer.write_all(&self.authority_count.to_be_bytes())?;
        writer.write_all(&self.additional_count.to_be_bytes())?;
        Ok(12)
    }
}
#[derive(Debug, Copy, Clone)]
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
#[derive(Debug, Copy, Clone)]
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
#[derive(Debug, Copy, Clone)]
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
#[derive(Debug, Copy, Clone)]
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

pub fn be_u8_into<T: TryFrom<u8>>(bytes: &[u8]) -> nom::IResult<&[u8], T> {
    let (tail, bits1) = be_u8(bytes)?;
    let Ok(bits1) = bits1.try_into() else {
        return Err(Error(make_error(bytes, ErrorKind::Verify)));
    };
    Ok((tail, bits1))
}

pub fn be_u16_into<T: TryFrom<u16>>(bytes: &[u8]) -> nom::IResult<&[u8], T> {
    let (tail, bits1) = be_u16(bytes)?;
    let Ok(bits1) = bits1.try_into() else {
        return Err(Error(make_error(bytes, ErrorKind::Verify)));
    };
    Ok((tail, bits1))
}

pub fn parse_header(bytes: &[u8]) -> nom::IResult<&[u8], DnsHeader> {
    let (bytes, (id, bits1, bits2, question_count, answer_count, authority_count, additional_count))
        = (be_u16, be_u8_into, be_u8_into, be_u16, be_u16, be_u16, be_u16).parse(bytes)?;
    let header = DnsHeader{
        id,
        bits1,
        bits2,
        question_count,
        answer_count,
        authority_count,
        additional_count,
    };
    Ok((bytes, header))
}
