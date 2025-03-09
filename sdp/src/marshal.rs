// https://github.com/pion/sdp/blob/c128a97b2dd802c25c35c45775baaafe7e61434f/marshal.go

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

use crate::session_description::SessionDescription;

// Marshal takes a SDP struct to text
// https://tools.ietf.org/html/rfc4566#section-5
// Session description
//
//     v=  (protocol version)
//     o=  (originator and session identifier)
//     s=  (session name)
//     i=* (session information)
//     u=* (URI of description)
//     e=* (email address)
//     p=* (phone number)
//     c=* (connection information -- not required if included in
//          all media)
//     b=* (zero or more bandwidth information lines)
//     One or more time descriptions ("t=" and "r=" lines; see below)
//     z=* (time zone adjustments)
//     k=* (encryption key)
//     a=* (zero or more session attribute lines)
//     Zero or more media descriptions
//
// Time description
//
//     t=  (time the session is active)
//     r=* (zero or more repeat times)
//
// Media description, if present
//
//     m=  (media name and transport address)
//     i=* (media title)
//     c=* (connection information -- optional if included at
//          session level)
//     b=* (zero or more bandwidth information lines)
//     k=* (encryption key)
//     a=* (zero or more media attribute lines)
impl SessionDescription {
    pub fn marshal(&self) -> Result<Vec<u8>, String> {
        let marsh = Marshaller::with_capacity(self.marshal_size());

        marsh.add_key_value("v=", self.version.marshal_into);
        marsh.add_key_value("o=", self.origin.marshal_into);
        marsh.add_key_value("s=", self.session_name.marshal_into);

        if let Some(session_information) = &self.session_information {
            marsh.add_key_value("i=", session_information.marshal_into);
        }

        if let Some(uri) = &self.uri {
            marsh.append("u=".as_bytes());
            marsh.append(uri.to_string().as_bytes());
            marsh.append("\r\n".as_bytes());
        }

        if let Some(email_address) = &self.email_address {
            marsh.add_key_value("e=", email_address.marshal_into);
        }

        if let Some(phone_number) = &self.phone_number {
            marsh.add_key_value("p=", phone_number.marshal_into);
        }

        if let Some(connection_information) = &self.connection_information {
            marsh.add_key_value("c=", connection_information.marshal_into);
        }

        for b in &self.bandwidth {
            marsh.add_key_value("b=", b.marshal_into);
        }

        for td in &self.time_descriptions {
            marsh.add_key_value("t=", td.timing.marshal_into);
            for r in &td.repeat_times {
                marsh.add_key_value("r=", r.marshal_into);
            }
        }

        if !self.time_zones.is_empty() {
            marsh.append("z=".as_bytes());
            for (i, z) in self.time_zones.iter().enumerate() {
                if i > 0 {
                    marsh.append(" ".as_bytes());
                }
                marsh = z.marshal_into(marsh);
            }
            marsh.append("\r\n".as_bytes());
        }

        if let Some(encryption_key) = &self.encryption_key {
            marsh.add_key_value("k=", encryption_key.marshal_into);
        }

        for a in &self.attributes {
            marsh.add_key_value("a=", a.marshal_into);
        }

        for md in &self.media_descriptions {
            marsh.add_key_value("m=", md.media_name.marshal_into);

            if let Some(media_title) = &md.media_title {
                marsh.add_key_value("i=", media_title.marshal_into);
            }

            if let Some(connection_information) = &md.connection_information {
                marsh.add_key_value("c=", connection_information.marshal_into);
            }

            for b in &md.bandwidth {
                marsh.add_key_value("b=", b.marshal_into);
            }

            if let Some(encryption_key) = &md.encryption_key {
                marsh.add_key_value("k=", encryption_key.marshal_into);
            }

            for a in &md.attributes {
                marsh.add_key_value("a=", a.marshal_into);
            }
        }

        Ok(marsh)
    }
}

/// `$type=` and CRLF size.
const LINE_BASE_SIZE: usize = 4;

// MarshalSize returns the size of the SessionDescription once marshaled.
func (s *SessionDescription) MarshalSize() (marshalSize int) { //nolint:cyclop
    marshalSize += LINE_BASE_SIZE     + self.version.marshalSize()
    marshalSize += LINE_BASE_SIZE     + self.origin.marshalSize()
    marshalSize += LINE_BASE_SIZE     + self.session_name.marshalSize()

    if s.SessionInformation != nil {
        marshalSize += LINE_BASE_SIZE     + s.SessionInformation.marshalSize()
    }

    if s.URI != nil {
        marshalSize += LINE_BASE_SIZE     + len(s.URI.String())
    }

    if s.EmailAddress != nil {
        marshalSize += LINE_BASE_SIZE     + s.EmailAddress.marshalSize()
    }

    if s.PhoneNumber != nil {
        marshalSize += LINE_BASE_SIZE     + s.PhoneNumber.marshalSize()
    }

    if s.ConnectionInformation != nil {
        marshalSize += LINE_BASE_SIZE     + s.ConnectionInformation.marshalSize()
    }

    for _, b := range s.Bandwidth {
        marshalSize += LINE_BASE_SIZE     + b.marshalSize()
    }

    for _, td := range s.TimeDescriptions {
        marshalSize += LINE_BASE_SIZE     + td.Timing.marshalSize()
        for _, r := range td.RepeatTimes {
            marshalSize += LINE_BASE_SIZE     + r.marshalSize()
        }
    }

    if len(s.TimeZones) > 0 {
        marshalSize += LINE_BASE_SIZE

        for i, z := range s.TimeZones {
            if i > 0 {
                marshalSize++
            }
            marshalSize += z.marshalSize()
        }
    }

    if s.EncryptionKey != nil {
        marshalSize += LINE_BASE_SIZE     + s.EncryptionKey.marshalSize()
    }

    for _, a := range s.Attributes {
        marshalSize += LINE_BASE_SIZE     + a.marshalSize()
    }

    for _, md := range s.MediaDescriptions {
        marshalSize += LINE_BASE_SIZE     + md.MediaName.marshalSize()
        if md.MediaTitle != nil {
            marshalSize += LINE_BASE_SIZE     + md.MediaTitle.marshalSize()
        }
        if md.ConnectionInformation != nil {
            marshalSize += LINE_BASE_SIZE     + md.ConnectionInformation.marshalSize()
        }

        for _, b := range md.Bandwidth {
            marshalSize += LINE_BASE_SIZE     + b.marshalSize()
        }

        if md.EncryptionKey != nil {
            marshalSize += LINE_BASE_SIZE     + md.EncryptionKey.marshalSize()
        }

        for _, a := range md.Attributes {
            marshalSize += LINE_BASE_SIZE     + a.marshalSize()
        }
    }

    return marshalSize
}

/// marshaller contains state during marshaling.
type Marshaller = Vec<u8>;

impl Marshaller {
    pub fn add_key_value(&mut self, key: &str, value: func([]byte) []byte) {
        self.append(key.as_bytes());
        *self = value(self);
        self.append("\r\n".as_bytes());
    }
}

pub(crate) fn len_uint(i: u64) -> usize {
    if i == 0 {
        return 1;
    }

    let mut count = 0;
    while i != 0 {
        i /= 10;
        count += 1;
    }

    count
}

pub(crate) fn len_int(i: i64) -> usize {
    if i < 0 {
        return len_uint((-i) as u64) + 1;
    }

    len_uint(i as u64)
}

pub(crate) fn string_from_marshal(marshal_func: fn([]byte) -> []byte, size_func: fn() -> usize) -> String {
    return string(marshal_func(Vec::with_capacity(size_func())))
}
