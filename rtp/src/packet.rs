// https://github.com/pion/rtp/blob/ee5524bed13b5f257ae7083ba4923001b59dfa59/packet.go

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

use crate::error::RtpError;
use std::io;

/// Extension RTP Header extension.
#[derive(Clone, Debug, PartialEq)]
pub struct Extension {
    id: u8,
    payload: Vec<u8>,
}

/// Header represents an RTP packet header.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Header {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrc: Vec<u32>,
    pub extension_profile: u16,
    pub extensions: Vec<Extension>,

    /// Deprecated: will be removed in a future version.
    #[deprecated]
    pub payload_offset: usize,
}

/// Packet represents an RTP Packet.
#[derive(Debug, Default, PartialEq)]
pub struct Packet {
    pub header: Header,
    pub payload: Vec<u8>,
    pub padding_size: u8,

    /// Deprecated: will be removed in a future version.
    #[deprecated]
    pub raw: Vec<u8>,
}

const HEADER_LENGTH: usize = 4;
const VERSION_SHIFT: u8 = 6;
const VERSION_MASK: u8 = 0x3;
const PADDING_SHIFT: u8 = 5;
const PADDING_MASK: u8 = 0x1;
const EXTENSION_SHIFT: u8 = 4;
const EXTENSION_MASK: u8 = 0x1;
const EXTENSION_PROFILE_ONE_BYTE: u16 = 0xBEDE;
const EXTENSION_PROFILE_TWO_BYTE: u16 = 0x1000;
const EXTENSION_ID_RESERVED: u8 = 0xF;
const CC_MASK: u8 = 0xF;
const MARKER_SHIFT: u8 = 7;
const MARKER_MASK: u8 = 0x1;
const PT_MASK: u8 = 0x7F;
const SEQ_NUM_OFFSET: usize = 2;
const SEQ_NUM_LENGTH: usize = 2;
const TIMESTAMP_OFFSET: usize = 4;
const TIMESTAMP_LENGTH: usize = 4;
const SSRC_OFFSET: usize = 8;
const SSRC_LENGTH: usize = 4;
const CSRC_OFFSET: usize = 12;
const CSRC_LENGTH: usize = 4;

impl Packet {
    /// String helps with debugging by printing packet information in a readable way.
    pub fn string(&self) -> String {
        let mut out = String::from("RTP PACKET:\n");

        out += &format!("\tVersion: {}\n", self.header.version);
        out += &format!("\tMarker: {}\n", self.header.marker);
        out += &format!("\tPayload Type: {}\n", self.header.payload_type);
        out += &format!("\tSequence Number: {}\n", self.header.sequence_number);
        out += &format!("\tTimestamp: {}\n", self.header.timestamp);
        out += &format!("\tSSRC: {} ({})\n", self.header.ssrc, self.header.ssrc);
        out += &format!("\tPayload Length: {}\n", self.payload.len());

        out
    }
}

impl Header {
    /// Unmarshal parses the passed byte slice and stores the result in the Header.
    /// It returns the number of bytes read n and any error.
    pub fn unmarshal(&mut self, buf: &[u8]) -> Result<usize, RtpError> {
        if buf.len() < HEADER_LENGTH {
            return Err(RtpError::HeaderSizeInsufficient(
                "%w: %d < %d",
                buf.len(),
                HEADER_LENGTH,
            ));
        }

        /*
         *  0                   1                   2                   3
         *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |V=2|P|X|  CC   |M|     PT      |       sequence number         |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |                           timestamp                           |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |           synchronization source (SSRC) identifier            |
         * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         * |            contributing source (CSRC) identifiers             |
         * |                             ....                              |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */

        self.version = (buf[0] >> VERSION_SHIFT) & VERSION_MASK;
        self.padding = ((buf[0] >> PADDING_SHIFT) & PADDING_MASK) > 0;
        self.extension = ((buf[0] >> EXTENSION_SHIFT) & EXTENSION_MASK) > 0;
        let n_csrc = (buf[0] & CC_MASK) as usize;
        if self.csrc.capacity() < n_csrc || self.csrc.is_empty() {
            self.csrc = Vec::with_capacity(n_csrc);
        } else {
            self.csrc.resize(n_csrc, 0);
        }

        let mut n = CSRC_OFFSET + (n_csrc * CSRC_LENGTH);
        if buf.len() < n {
            return Err(RtpError::HeaderSizeInsufficient(
                "size %d < %d: %w",
                buf.len(),
                n,
            ));
        }

        self.marker = ((buf[1] >> MARKER_SHIFT) & MARKER_MASK) > 0;
        self.payload_type = buf[1] & PT_MASK;

        self.sequence_number = u16::from_be_bytes([buf[SEQ_NUM_OFFSET], buf[SEQ_NUM_OFFSET + 1]]);
        self.timestamp = u32::from_be_bytes([
            buf[TIMESTAMP_OFFSET],
            buf[TIMESTAMP_OFFSET + 1],
            buf[TIMESTAMP_OFFSET + 2],
            buf[TIMESTAMP_OFFSET + 3],
        ]);
        self.ssrc = u32::from_be_bytes([
            buf[SSRC_OFFSET],
            buf[SSRC_OFFSET + 1],
            buf[SSRC_OFFSET + 2],
            buf[SSRC_OFFSET + 3],
        ]);

        for i in 0..self.csrc.len() {
            let offset = CSRC_OFFSET + (i * CSRC_LENGTH);
            self.csrc[i] = u32::from_be_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]);
        }

        self.extensions.clear();

        if self.extension {
            let expected = n + 4;
            if buf.len() < expected {
                return Err(RtpError::HeaderSizeInsufficientForExtension(
                    "size %d < %d: %w",
                    buf.len(),
                    expected,
                ));
            }

            self.extension_profile = u16::from_be_bytes([buf[n], buf[n + 1]]);
            n += 2;
            let extension_length = (u16::from_be_bytes([buf[n], buf[n + 1]]) as usize) * 4;
            n += 2;
            let extension_end = n + extension_length;

            if buf.len() < extension_end {
                return Err(RtpError::HeaderSizeInsufficientForExtension(
                    "size %d < %d: %w",
                    buf.len(),
                    extension_end,
                ));
            }

            if self.extension_profile == EXTENSION_PROFILE_ONE_BYTE
                || self.extension_profile == EXTENSION_PROFILE_TWO_BYTE
            {
                let mut extid: u8;
                let mut payload_len: usize;

                while n < extension_end {
                    // padding
                    if buf[n] == 0x00 {
                        n += 1;

                        continue;
                    }

                    if self.extension_profile == EXTENSION_PROFILE_ONE_BYTE {
                        extid = buf[n] >> 4;
                        payload_len = ((buf[n] & !0xF0) + 1) as usize;
                        n += 1;

                        if extid == EXTENSION_ID_RESERVED {
                            break;
                        }
                    } else {
                        extid = buf[n];
                        n += 1;

                        if buf.len() <= n {
                            return Err(RtpError::HeaderSizeInsufficientForExtension(
                                "size %d < %d: %w",
                                buf.len(),
                                n,
                            ));
                        }

                        payload_len = buf[n] as usize;
                        n += 1;
                    }

                    let extension_payload_end = n + payload_len;
                    if buf.len() <= extension_payload_end {
                        return Err(RtpError::HeaderSizeInsufficientForExtension(
                            "size %d < %d: %w",
                            buf.len(),
                            extension_payload_end,
                        ));
                    }

                    let extension = Extension {
                        id: extid,
                        payload: buf[n..n + payload_len].to_vec(),
                    };
                    self.extensions.push(extension);
                    n += payload_len;
                }
            } else {
                // RFC3550 Extension
                let extension = Extension {
                    id: 0,
                    payload: buf[n..extension_end].to_vec(),
                };
                self.extensions.push(extension);
                n += self.extensions[0].payload.len();
            }
        }

        Ok(n)
    }
}

impl Packet {
    /// Unmarshal parses the passed byte slice and stores the result in the Packet.
    pub fn unmarshal(&mut self, buf: &[u8]) -> Result<(), RtpError> {
        let n = self.header.unmarshal(buf)?;

        let mut end = buf.len();
        if self.header.padding {
            if end <= n {
                return Err(RtpError::TooSmall);
            }
            self.padding_size = buf[end - 1];
            end = end.saturating_sub(self.padding_size as usize);
        } else {
            self.padding_size = 0;
        }
        if end < n {
            return Err(RtpError::TooSmall);
        }

        self.payload = buf[n..end].to_vec();

        Ok(())
    }
}

impl Header {
    /// Marshal serializes the header into bytes.
    pub fn marshal(&self) -> Result<Vec<u8>, RtpError> {
        let mut buf = vec![0u8; self.marshal_size()];

        let n = self.marshal_to(&mut buf)?;

        Ok(buf[..n].to_vec())
    }

    /// MarshalTo serializes the header and writes to the buffer.
    pub fn marshal_to(&self, buf: &mut [u8]) -> Result<usize, RtpError> {
        /*
         *  0                   1                   2                   3
         *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |V=2|P|X|  CC   |M|     PT      |       sequence number         |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |                           timestamp                           |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |           synchronization source (SSRC) identifier            |
         * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         * |            contributing source (CSRC) identifiers             |
         * |                             ....                              |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */

        let size = self.marshal_size();
        if size > buf.len() {
            return Err(io.ErrShortBuffer);
        }

        // The first byte contains the version, padding bit, extension bit,
        // and csrc size.
        buf[0] = (self.version << VERSION_SHIFT) | (self.csrc.len() as u8);
        if self.padding {
            buf[0] |= 1 << PADDING_SHIFT;
        }

        if self.extension {
            buf[0] |= 1 << EXTENSION_SHIFT;
        }

        // The second byte contains the marker bit and payload type.
        buf[1] = self.payload_type;
        if self.marker {
            buf[1] |= 1 << MARKER_SHIFT;
        }

        buf[2..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ssrc.to_be_bytes());

        let mut n = 12;
        for csrc in &self.csrc {
            buf[n..n + 4].copy_from_slice(&csrc.to_be_bytes());
            n += 4;
        }

        if self.extension {
            let ext_header_pos = n;
            buf[n..n + 2].copy_from_slice(&self.extension_profile.to_be_bytes());
            n += 4;
            let start_extensions_pos = n;

            match self.extension_profile {
                // RFC 8285 RTP One Byte Header Extension
                EXTENSION_PROFILE_ONE_BYTE => {
                    for extension in &self.extensions {
                        let payload_len = extension.payload.len();
                        buf[n] = (extension.id << 4) | ((payload_len as u8) - 1);
                        n += 1;
                        buf[n..n + payload_len].copy_from_slice(&extension.payload);
                        n += payload_len;
                    }
                }
                // RFC 8285 RTP Two Byte Header Extension
                EXTENSION_PROFILE_TWO_BYTE => {
                    for extension in &self.extensions {
                        let payload_len = extension.payload.len();
                        buf[n] = extension.id;
                        n += 1;
                        buf[n] = payload_len as u8;
                        n += 1;
                        buf[n..n + payload_len].copy_from_slice(&extension.payload);
                        n += payload_len;
                    }
                }
                // RFC3550 Extension
                _ => {
                    let extlen = self.extensions[0].payload.len();
                    if extlen % 4 != 0 {
                        // the payload must be in 32-bit words.
                        return Err(io.ErrShortBuffer);
                    }
                    buf[n..n + extlen].copy_from_slice(&self.extensions[0].payload);
                    n += extlen;
                }
            }

            // calculate extensions size and round to 4 bytes boundaries
            let ext_size = n - start_extensions_pos;
            let rounded_ext_size = ((ext_size + 3) / 4) * 4;

            buf[ext_header_pos + 2..ext_header_pos + 4]
                .copy_from_slice(&(rounded_ext_size / 4).to_be_bytes());

            // add padding to reach 4 bytes boundaries
            for i in 0..(rounded_ext_size - ext_size) {
                buf[n] = 0;
                n += 1;
            }
        }

        Ok(n)
    }

    /// MarshalSize returns the size of the header once marshaled.
    pub fn marshal_size(&self) -> usize {
        // NOTE: Be careful to match the MarshalTo() method.
        let mut size = 12 + (self.csrc.len() * CSRC_LENGTH);

        if self.extension {
            let mut ext_size = 4;

            match self.extension_profile {
                // RFC 8285 RTP One Byte Header Extension
                EXTENSION_PROFILE_ONE_BYTE => {
                    for extension in &self.extensions {
                        ext_size += 1 + extension.payload.len();
                    }
                }
                // RFC 8285 RTP Two Byte Header Extension
                EXTENSION_PROFILE_TWO_BYTE => {
                    for extension in &self.extensions {
                        ext_size += 2 + extension.payload.len();
                    }
                }
                _ => {
                    ext_size += self.extensions[0].payload.len();
                }
            }

            // extensions size must have 4 bytes boundaries
            size += ((ext_size + 3) / 4) * 4;
        }

        size
    }

    /// SetExtension sets an RTP header extension.
    pub fn set_extension(&mut self, id: u8, payload: &[u8]) -> Result<(), RtpError> {
        if self.extension {
            match self.extension_profile {
                // RFC 8285 RTP One Byte Header Extension
                EXTENSION_PROFILE_ONE_BYTE => {
                    if id < 1 || id > 14 {
                        return Err(RtpError::Rfc8285OneByteHeaderIdRange("%w actual(%d)", id));
                    }
                    if payload.len() > 16 {
                        return Err(RtpError::Rfc8285OneByteHeaderSize(
                            "%w actual(%d)",
                            payload.len(),
                        ));
                    }
                }
                // RFC 8285 RTP Two Byte Header Extension
                EXTENSION_PROFILE_TWO_BYTE => {
                    if id < 1 {
                        return Err(RtpError::Rfc8285TwoByteHeaderIdRange("%w actual(%d)", id));
                    }
                    if payload.len() > 255 {
                        return Err(RtpError::Rfc8285TwoByteHeaderSize(
                            "%w actual(%d)",
                            payload.len(),
                        ));
                    }
                }
                // RFC3550 Extension
                _ => {
                    if id != 0 {
                        return Err(RtpError::Rfc3550HeaderIdRange("%w actual(%d)", id));
                    }
                }
            }

            // Update existing if it exists else add new extension
            for extension in &mut self.extensions {
                if extension.id == id {
                    extension.payload = payload.to_vec();

                    return Ok(());
                }
            }

            self.extensions.push(Extension {
                id,
                payload: payload.to_vec(),
            });

            return Ok(());
        }

        // No existing header extensions
        self.extension = true;

        let payload_len = payload.len();
        if payload_len <= 16 {
            self.extension_profile = EXTENSION_PROFILE_ONE_BYTE;
        } else if payload_len > 16 && payload_len < 256 {
            self.extension_profile = EXTENSION_PROFILE_TWO_BYTE;
        }

        self.extensions.push(Extension {
            id,
            payload: payload.to_vec(),
        });

        Ok(())
    }

    /// GetExtensionIDs returns an extension id array.
    pub fn get_extension_ids(&self) -> Vec<u8> {
        if !self.extension {
            return Vec::new();
        }

        if self.extensions.is_empty() {
            return Vec::new();
        }

        let ids = self.extensions.iter().map(|ext| ext.id).collect();

        return ids;
    }

    /// GetExtension returns an RTP header extension.
    pub fn get_extension(&self, id: u8) -> Vec<u8> {
        if !self.extension {
            return Vec::new();
        }
        for extension in &self.extensions {
            if extension.id == id {
                return extension.payload.clone();
            }
        }

        Vec::new()
    }

    /// DelExtension Removes an RTP Header extension.
    pub fn del_extension(&mut self, id: u8) -> Result<(), RtpError> {
        if !self.extension {
            return Err(RtpError::HeaderExtensionsNotEnabled);
        }
        for (i, extension) in self.extensions.iter().enumerate() {
            if extension.id == id {
                self.extensions.remove(i);

                return Ok(());
            }
        }

        Err(RtpError::HeaderExtensionNotFound)
    }
}

impl Packet {
    /// Marshal serializes the packet into bytes.
    pub fn marshal(&self) -> Result<Vec<u8>, RtpError> {
        let mut buf = vec![0u8; self.marshal_size()];

        let n = self.marshal_to(&mut buf)?;

        Ok(buf[..n].to_vec())
    }

    /// MarshalTo serializes the packet and writes to the buffer.
    pub fn marshal_to(&self, buf: &mut [u8]) -> Result<usize, RtpError> {
        if self.header.padding && self.padding_size == 0 {
            return Err(RtpError::InvalidRtpPadding);
        }

        let mut n = self.header.marshal_to(buf)?;

        // Make sure the buffer is large enough to hold the packet.
        if n + self.payload.len() + (self.padding_size as usize) > buf.len() {
            return Err(io.ErrShortBuffer);
        }

        let m = self.payload.len();
        buf[n..n + m].copy_from_slice(&self.payload);

        if self.header.padding {
            buf[n + m + (self.padding_size as usize) - 1] = self.padding_size;
        }

        return Ok(n + m + (self.padding_size as usize));
    }

    // MarshalSize returns the size of the packet once marshaled.
    pub fn marshal_size(&self) -> usize {
        self.header.marshal_size() + self.payload.len() + (self.padding_size as usize)
    }
}

// https://github.com/pion/rtp/blob/ee5524bed13b5f257ae7083ba4923001b59dfa59/packet_test.go

#[test]
fn test_basic() {
    let mut packet = Packet::default();

    let result = packet.unmarshal(&[]);
    assert!(
        result.is_err(),
        "Unmarshal did not error on zero length packet"
    );

    let raw_pkt = vec![
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x00, 0x01, 0x00,
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x98, 0x36, 0xbe, 0x88, 0x9e,
    ];
    let parsed_packet = Packet {
        header: Header {
            padding: false,
            marker: true,
            extension: true,
            extension_profile: 1,
            extensions: vec![Extension {
                id: 0,
                payload: vec![0xFF, 0xFF, 0xFF, 0xFF],
            }],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            csrc: Vec::new(),
            ..Default::default()
        },
        payload: raw_pkt[20..].to_vec(),
        padding_size: 0,
        ..Default::default()
    };

    // Unmarshal to the used Packet should work as well.
    for _ in 0..2 {
        let result = packet.unmarshal(&raw_pkt);
        assert!(result.is_ok(), result);
        assert_eq!(
            packet, parsed_packet,
            "TestBasic unmarshal: got {:?}, want {:?}",
            packet, parsed_packet
        );

        assert_eq!(
            parsed_packet.header.marshal_size(),
            20,
            "wrong computed header marshal size"
        );
        assert_eq!(
            parsed_packet.marshal_size(),
            raw_pkt.len(),
            "wrong computed marshal size"
        );

        match packet.marshal() {
            Ok(raw) => {
                assert_eq!(
                    raw, raw_pkt,
                    "TestBasic marshal: got {:?}, want {:?}",
                    raw, raw_pkt
                );
            }
            Err(err) => {
                assert!(false, "{}", err);
            }
        }
    }

    // packet with padding
    let raw_pkt = vec![
        0xb0, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x00, 0x01, 0x00,
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x98, 0x36, 0xbe, 0x88, 0x04,
    ];
    let parsed_packet = Packet {
        header: Header {
            padding: true,
            marker: true,
            extension: true,
            extension_profile: 1,
            extensions: vec![Extension {
                id: 0,
                payload: vec![0xFF, 0xFF, 0xFF, 0xFF],
            }],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            csrc: Vec::new(),
            ..Default::default()
        },
        payload: raw_pkt[20..21].to_vec(),
        padding_size: 4,
        ..Default::default()
    };
    let result = packet.unmarshal(&raw_pkt);
    assert!(result.is_ok(), result);
    assert_eq!(
        packet, parsed_packet,
        "TestBasic padding unmarshal: got {:?}, want {:?}",
        packet, parsed_packet
    );

    // packet with zero padding following packet with non-zero padding
    let raw_pkt = vec![
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x00, 0x01, 0x00,
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x98, 0x36, 0xbe, 0x88, 0x9e,
    ];
    let parsed_packet = Packet {
        header: Header {
            padding: false,
            marker: true,
            extension: true,
            extension_profile: 1,
            extensions: vec![Extension {
                id: 0,
                payload: vec![0xFF, 0xFF, 0xFF, 0xFF],
            }],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            csrc: Vec::new(),
            ..Default::default()
        },
        payload: raw_pkt[20..].to_vec(),
        padding_size: 0,
        ..Default::default()
    };
    let result = packet.unmarshal(&raw_pkt);
    assert!(result.is_ok(), result);
    assert_eq!(
        packet, parsed_packet,
        "TestBasic zero padding unmarshal: got {:?}, want {:?}",
        packet, parsed_packet
    );

    // packet with only padding
}
