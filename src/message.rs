use std::error::Error;
use std::fmt::{Display, Formatter};
use anyhow::Context;

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
#[derive(Default)]
#[repr(C)]
pub(crate) struct DnsHeaderRaw {
    id: [u8; 2],
    bits: [u8; 2],
    question_count: [u8; 2],
    answer_count: [u8; 2],
    authority_count: [u8; 2],
    additional_count: [u8; 2],
}
impl DnsHeader {
    pub(crate) fn get_raw(&self) -> DnsHeaderRaw {
        DnsHeaderRaw {
            id: self.id.to_be_bytes(),
            bits: [self.bits1.into(), self.bits2.into()],
            question_count: self.question_count.to_be_bytes(),
            answer_count: self.answer_count.to_be_bytes(),
            authority_count: self.authority_count.to_be_bytes(),
            additional_count: self.additional_count.to_be_bytes(),
        }
    }
}
impl DnsHeaderRaw {
    pub fn parse(&self) -> anyhow::Result<DnsHeader> {
        let res = DnsHeader {
            id: u16::from_be_bytes(self.id),
            bits1: DnsHeaderBits1::try_from(self.bits[0]).context("failed to parse bits1")?,
            bits2: DnsHeaderBits2::try_from(self.bits[1]).context("failed to parse bits2")?,
            question_count: u16::from_be_bytes(self.question_count),
            answer_count: u16::from_be_bytes(self.answer_count),
            authority_count: u16::from_be_bytes(self.authority_count),
            additional_count: u16::from_be_bytes(self.additional_count),
        };
        Ok(res)
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
impl Error for ConversionError {}
