// https://github.com/pion/sdp/blob/c128a97b2dd802c25c35c45775baaafe7e61434f/common_description.go

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

use crate::marshal::{len_int, len_uint, string_from_marshal};

/// Information describes the "i=" field which provides textual information
/// about the session.
pub struct Information(pub String);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", string_from_marshal(self.marshal_into, self.marshal_size))
    }
}

impl Information {
    fn marshal_into(&self, b: &mut Vec<u8>) -> Vec<u8> {
        // return append(b, i...)
        b.extend_from_slice(self.0.as_bytes());
    }

    fn marshal_size(&self) -> usize {
        self.0.len()
    }
}

/// ConnectionInformation defines the representation for the "c=" field
/// containing connection data.
pub struct ConnectionInformation {
    pub network_type: String,
    pub address_type: String,
    pub address: Option<Address>,
}

impl fmt::Display for ConnectionInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", string_from_marshal(self.marshal_into, self.marshal_size))
    }
}

impl ConnectionInformation {
    fn marshal_into(&self, b: &mut Vec<u8>) -> Vec<u8> {
        b.extend_from_slice(self.network_type.as_bytes());
        b.push(b' ');
        b.extend_from_slice(self.address_type.as_bytes());

        if let Some(addr) = &self.address {
            b.push(b' ');
            addr.marshal_into(b);
        }
    }

    fn marshal_size(&self) -> usize {
        let mut size = self.network_type.len();
        size += 1 + self.address_type.len();
        if let Some(addr) = &self.address {
            size += 1 + addr.marshal_size();
        }

        size
    }
}
func (c ConnectionInformation) marshalInto(b []byte) []byte {
    b = append(append(b, c.NetworkType...), ' ')
    b = append(b, c.AddressType...)

    if c.Address != nil {
        b = append(b, ' ')
        b = c.Address.marshalInto(b)
    }

    return b
}

/// Address desribes a structured address token from within the "c=" field.
pub struct Address {
    pub address: String,
    pub ttl: Option<int>,
    pub range: Option<int>,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", string_from_marshal(self.marshal_into, self.marshal_size))
    }
}

impl Address {
    fn marshal_into(&self, b: &mut Vec<u8>) -> Vec<u8> {
        b.extend_from_slice(self.address.as_bytes());
        if let Some(ttl) = self.ttl {
            b.push(b'/');
            write!(b, "{}", ttl).unwrap();
        }
        if let Some(range) = self.range {
            b.push(b'/');
            write!(b, "{}", range).unwrap();
        }

        b
    }

    fn marshal_size(&self) -> usize {
        let mut size = self.address.len();
        if let Some(ttl) = self.ttl {
            size += 1 + len_uint(ttl as u64);
        }
        if let Some(range) = self.range {
            size += 1 + len_uint(range as u64);
        }

        size
    }
}
func (c *Address) marshalInto(b []byte) []byte {
    b = append(b, c.Address...)
    if c.TTL != nil {
        b = append(b, '/')
        b = strconv.AppendInt(b, int64(*c.TTL), 10)
    }
    if c.Range != nil {
        b = append(b, '/')
        b = strconv.AppendInt(b, int64(*c.Range), 10)
    }

    return b
}

/// Bandwidth describes an optional field which denotes the proposed bandwidth
/// to be used by the session or media.
pub struct Bandwidth {
    pub experimental: bool,
    pub r#type: String,
    pub bandwidth: u64,
}

impl fmt::Display for Bandwidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", string_from_marshal(self.marshal_into, self.marshal_size))
    }
}

impl Bandwidth {
    fn marshal_into(&self, b: &mut Vec<u8>) -> Vec<u8> {
        if self.experimental {
            b.extend_from_slice(b"X-");
        }
        buffer.extend_from_slice(self.r#type.as_bytes());
        buffer.push(b':');
        write!(buffer, "{}", self.bandwidth).unwrap();
    }

    fn marshal_size(&self) -> usize {
        let mut size = 0;
        if self.experimental {
            size += 2;
        }

        size += self.r#type.len()
            + 1
            + len_uint(self.bandwidth);

        size
    }
}
func (b Bandwidth) marshalInto(d []byte) []byte {
    if b.Experimental {
        d = append(d, "X-"...)
    }
    d = append(append(d, b.Type...), ':')

    return strconv.AppendUint(d, b.Bandwidth, 10)
}

/// EncryptionKey describes the "k=" which conveys encryption key information.
pub struct EncryptionKey(pub String);

impl fmt::Display for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", string_from_marshal(self.marshal_into, self.marshal_size))
    }
}

impl EncryptionKey {
    fn marshal_into(&self, buffer: &mut Vec<u8>) -> Vec<u8> {
        // return append(b, e...)
        buffer.extend_from_slice(self.0.as_bytes());
    }

    fn marshal_size(&self) -> usize {
        self.0.len()
    }
}

/// Attribute describes the "a=" field which represents the primary means for
/// extending SDP.
#[derive(Default)]
pub struct Attribute {
    pub key: String,
    pub value: String,
}

impl Attribute {
    /// NewPropertyAttribute constructs a new attribute.
    pub fn new_property_attribute(key: &str) -> Attribute {
        Attribute {
            key: key.to_string(),
            ..Default::default()
        }
    }

    /// NewAttribute constructs a new attribute.
    pub fn new_attribute(key: &str, value: &str) -> Attribute {
        Attribute {
            key: key.to_string(),
            value: value.to_string(),
        }
    }
}

impl fmt::Display for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", string_from_marshal(self.marshal_into, self.marshal_size))
    }
}

impl Attribute {
    fn marshal_into(&self, b: &mut Vec<u8>) -> []byte {
        b.extend_from_slice(self.key.as_bytes());
        if !self.value.is_empty() {
            b.push(b':');
            b.extend_from_slice(self.value.as_bytes());
        }

        b
    }

    fn marshal_size(&self) -> usize {
        let mut size = self.key.len();
        if !self.value.is_empty() {
            size += 1 + self.value.len();
        }

        size
    }
}

func (a Attribute) marshalInto(b []byte) []byte {
    b = append(b, a.Key...)
    if len(a.Value) > 0 {
        b = append(append(b, ':'), a.Value...)
    }

    return b
}

impl Attribute {
    /// IsICECandidate returns true if the attribute key equals "candidate".
    pub fn is_ice_candidate() -> bool {
        self.key == "candidate"
    }
}
