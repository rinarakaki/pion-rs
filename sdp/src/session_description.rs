// https://github.com/pion/sdp/blob/c128a97b2dd802c25c35c45775baaafe7e61434f/session_description.go#

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

use crate::common_description::{Attribute, Bandwidth, ConnectionInformation, EncryptionKey, Information};
use crate::marshal::{len_int, string_from_marshal};

/// SessionDescription is a a well-defined format for conveying sufficient
/// information to discover and participate in a multimedia session.
pub struct SessionDescription {
    /// v=0
    /// https://tools.ietf.org/html/rfc4566#section-5.1
    pub version: Version,

    /// o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
    /// https://tools.ietf.org/html/rfc4566#section-5.2
    pub origin: Origin,

    /// s=<session name>
    /// https://tools.ietf.org/html/rfc4566#section-5.3
    pub session_name: SessionName,

    /// i=<session description>
    /// https://tools.ietf.org/html/rfc4566#section-5.4
    pub session_information: Option<Information>,

    /// u=<uri>
    /// https://tools.ietf.org/html/rfc4566#section-5.5
    pub uri: Option<Uri>,

    /// e=<email-address>
    /// https://tools.ietf.org/html/rfc4566#section-5.6
    pub email_address: Option<EmailAddress>,

    /// p=<phone-number>
    /// https://tools.ietf.org/html/rfc4566#section-5.6
    pub phone_number: Option<PhoneNumber>,

    /// c=<nettype> <addrtype> <connection-address>
    /// https://tools.ietf.org/html/rfc4566#section-5.7
    pub connection_information: Option<ConnectionInformation>,

    /// b=<bwtype>:<bandwidth>
    /// https://tools.ietf.org/html/rfc4566#section-5.8
    pub bandwidth: Vec<Bandwidth>,

    /// https://tools.ietf.org/html/rfc4566#section-5.9
    /// https://tools.ietf.org/html/rfc4566#section-5.10
    pub time_descriptions: Vec<TimeDescription>,

    /// z=<adjustment time> <offset> <adjustment time> <offset> ...
    /// https://tools.ietf.org/html/rfc4566#section-5.11
    pub time_zones: Vec<TimeZone>,

    /// k=<method>
    /// k=<method>:<encryption key>
    /// https://tools.ietf.org/html/rfc4566#section-5.12
    pub encryption_key: Option<EncryptionKey>,

    /// a=<attribute>
    /// a=<attribute>:<value>
    /// https://tools.ietf.org/html/rfc4566#section-5.13
    pub attributes: Vec<Attribute>,

    /// https://tools.ietf.org/html/rfc4566#section-5.14
    pub media_descriptions: Vec<MediaDescription>,
}

impl SessionDescription {
    /// Attribute returns the value of an attribute and if it exists.
    pub fn attribute(&self, key: &str) -> Option<&str> {
        for a in &self.attributes {
            if a.key == key {
                return Some(a.value.as_str());
            }
        }
        None
    }
}

/// Version describes the value provided by the "v=" field which gives
/// the version of the Session Description Protocol.
pub struct Version(pub i64);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", string_from_marshal(self.marshal_into, self.marshal_size))
    }
}

impl Marshal for Version {
    fn marshal_into(&self, b: &mut String) {
        write!(b, "{}", self.0).unwrap();
    }

    fn marshal_size(&self) -> usize {
        len_int(self.0)
    }
}

/// Origin defines the structure for the "o=" field which provides the
/// originator of the session plus a session identifier and version number.
pub struct Origin {
    pub username: String,
    pub session_id: u64,
    pub session_version: u64,
    pub network_type: String,
    pub address_type: String,
    pub unicast_address: String,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", string_from_marshal(self.marshal_into, self.marshal_size))
    }
}

impl Origin {
    fn marshal_into(&self, b: []byte) -> []byte {
        b.push_str(&self.username);
        b.push(' ');

        write!(b, "{}", self.session_id).unwrap();
        b.push(' ');

        write!(b, "{}", self.session_version).unwrap();
        b.push(' ');

        b.push_str(&self.network_type);
        b.push(' ');

        b.push_str(&self.address_type);
        b.push(' ');

        b.push_str(&self.unicast_address);
    }

    fn marshal_size(&self) -> usize {
        self.username.len()
            + len_uint(self.session_id)
            + len_uint(self.session_version)
            + self.network_type.len()
            + self.address_type.len()
            + self.unicast_address.len()
            + 5
    }
}


func (o Origin) marshalInto(b []byte) []byte {
    b = append(append(b, o.Username...), ' ')
    b = append(strconv.AppendUint(b, o.SessionID, 10), ' ')
    b = append(strconv.AppendUint(b, o.SessionVersion, 10), ' ')
    b = append(append(b, o.NetworkType...), ' ')
    b = append(append(b, o.AddressType...), ' ')

    return append(b, o.UnicastAddress...)
}

/// SessionName describes a structured representations for the "s=" field
/// and is the textual session name.
pub type SessionName = String;

impl fmt::Display for SessionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", string_from_marshal(self.marshal_into, self.marshal_size))
    }
}

impl SessionName {
    fn marshal_into(&self, b: []byte) -> []byte {
        return append(b, s...)
    }

    fn marshal_size(&self) -> usize {
        self.len()
    }
}

/// EmailAddress describes a structured representations for the "e=" line
/// which specifies email contact information for the person responsible for
/// the conference.
pub type EmailAddress = String;

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", string_from_marshal(self.marshal_into, self.marshal_size))
    }
}

impl EmailAddress {
    fn marshal_into(&self, b: []byte) -> []byte {
        return append(b, e...)
    }

    fn marshal_size(&self) -> usize {
        self.len()
    }
}

/// PhoneNumber describes a structured representations for the "p=" line
/// specify phone contact information for the person responsible for the
/// conference.
pub type PhoneNumber = String;

impl fmt::Display for PhoneNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", string_from_marshal(self.marshal_into, self.marshal_size))
    }
}

impl PhoneNumber {
    fn marshal_into(&self, b: []byte) -> []byte {
        return append(b, p...)
    }

    fn marshal_size(&self) -> usize {
        self.len()
    }
}

/// TimeZone defines the structured object for "z=" line which describes
/// repeated sessions scheduling.
pub struct TimeZone {
    pub adjustment_time: u64,
    pub offset: i64,
}

impl fmt::Display for TimeZone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", string_from_marshal(self.marshal_into, self.marshal_size))
    }
}


impl Marshal for TimeZone {
    fn marshal_into(&self, buf: &mut String) -> []byte {
        write!(buf, "{} {}", self.adjustment_time, self.offset).unwrap();
    }

    fn marshal_size(&self) -> usize {
        len_uint(self.adjustment_time) + 1 + len_int(self.offset)
    }
}

func (z TimeZone) marshalInto(b []byte) []byte {
    b = strconv.AppendUint(b, z.AdjustmentTime, 10)
    b = append(b, ' ')

    return strconv.AppendInt(b, z.Offset, 10)
}
