/// https://github.com/pion/rtp/blob/ee5524bed13b5f257ae7083ba4923001b59dfa59/packet.go

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// import (
//     "encoding/binary"
// )
use std::fmt;
use std::io;

/// Extension RTP Header extension.
pub struct Extension {
    id: u8,
    payload: Vec<u8>,
}

/// Header represents an RTP packet header.
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
    pub payload_offset: int,
}

/// Packet represents an RTP Packet.
pub struct Packet {
    pub header: Header,
    pub payload: Vec<u8>,
    pub padding_size: u8,

    /// Deprecated: will be removed in a future version.
    #[deprecated]
    pub raw: Vec<u8>,
}

const HEADER_LENGTH: usize = 4;
const VERSION_SHIFT = 6;
const VERSION_MASK = 0x3;
const PADDING_SHIFT = 5;
const PADDING_MASK = 0x1;
const EXTENSION_SHIFT = 4;
const EXTENSION_MASK = 0x1;
const EXTENSION_PROFILE_ONE_BYTE: u16 = 0xBEDE;
const EXTENSION_PROFILE_TWO_BYTE: u16 = 0x1000;
const extensionIDReserved     = 0xF;
const CC_MASK = 0xF;
const MARKER_SHIFT = 7;
const MARKER_MASK = 0x1;
const ptMask                  = 0x7F;
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
        let mut out = "RTP PACKET:\n"

        out += format!("\tVersion: {}\n", self.header.version)
        out += format!("\tMarker: {}\n", self.header.marker)
        out += format!("\tPayload Type: {}\n", self.header.payload_type)
        out += format!("\tSequence Number: {}\n", self.header.sequence_number)
        out += format!("\tTimestamp: {}\n", self.header.timestamp)
        out += format!("\tSSRC: {} (%x)\n", self.header.ssrc, self.header.ssrc)
        out += format!("\tPayload Length: {}\n", self.payload.len())

        out
    }
}

impl Header {
    /// Unmarshal parses the passed byte slice and stores the result in the Header.
    /// It returns the number of bytes read n and any error.
    pub fn unmarshal(&mut self, buf: &[u8]) -> Result<n int, err error> {
        if buf.len() < HEADER_LENGTH {
            return 0, fmt.Errorf("%w: %d < %d", errHeaderSizeInsufficient, buf.len(), HEADER_LENGTH);
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

        self.version = buf[0] >> VERSION_SHIFT & VERSION_MASK;
        self.padding = (buf[0] >> PADDING_SHIFT & PADDING_MASK) > 0;
        self.extension = (buf[0] >> EXTENSION_SHIFT & EXTENSION_MASK) > 0;
        let n_csrc = buf[0] & CC_MASK as int;
        if cap(self.csrc) < n_csrc || self.csrc.is_empty() {
            self.csrc = Vec::with_capacity(n_csrc);
        } else {
            self.csrc = self.csrc[:n_csrc]
        }

        n = CSRC_OFFSET + (n_csrc * CSRC_LENGTH)
        if buf.len() < n {
            return n, fmt.Errorf("size %d < %d: %w", buf.len(), n,
                errHeaderSizeInsufficient);
        }

        self.marker = (buf[1] >> MARKER_SHIFT & MARKER_MASK) > 0;
        self.payload_type = buf[1] & ptMask;

        self.sequence_number = binary.BigEndian.Uint16(buf[SEQ_NUM_OFFSET : SEQ_NUM_OFFSET+SEQ_NUM_LENGTH]);
        self.timestamp = binary.BigEndian.Uint32(buf[TIMESTAMP_OFFSET : TIMESTAMP_OFFSET+TIMESTAMP_LENGTH]);
        self.ssrc = binary.BigEndian.Uint32(buf[SSRC_OFFSET : SSRC_OFFSET+SSRC_LENGTH]);

        for i := range self.csrc {
            let offset = CSRC_OFFSET + (i * CSRC_LENGTH);
            self.csrc[i] = binary.BigEndian.Uint32(buf[offset:]);
        }

        if self.extensions != nil {
            self.extensions = self.extensions[:0]
        }

        if self.extension {
            let expected = n + 4;
            if buf.len() < expected {
                return n, fmt.Errorf("size %d < %d: %w",
                    buf.len(), expected,
                    errHeaderSizeInsufficientForExtension,
                );
            }

            self.extension_profile = binary.BigEndian.Uint16(buf[n:]);
            n += 2;
            let extension_length = int(binary.BigEndian.Uint16(buf[n:])) * 4;
            n += 2;
            let extension_end = n + extension_length;

            if buf.len() < extension_end {
                return n, fmt.Errorf("size %d < %d: %w", buf.len(), extension_end, errHeaderSizeInsufficientForExtension);
            }

            if self.extension_profile == EXTENSION_PROFILE_ONE_BYTE || self.extension_profile == EXTENSION_PROFILE_TWO_BYTE {
                let mut extid: u8;
                var (

                    payloadLen int
                )

                for n < extensionEnd {
                    if buf[n] == 0x00 { // padding
                        n += 1;

                        continue
                    }

                    if self.extension_profile == EXTENSION_PROFILE_ONE_BYTE {
                        extid = buf[n] >> 4;
                        payloadLen = buf[n]&^0xF0 + 1 as int;
                        n += 1;

                        if extid == extensionIDReserved {
                            break
                        }
                    } else {
                        extid = buf[n]
                        n++

                        if buf.len() <= n {
                            return n, fmt.Errorf("size %d < %d: %w", buf.len(), n, errHeaderSizeInsufficientForExtension)
                        }

                        payloadLen = int(buf[n])
                        n++
                    }

                    if extensionPayloadEnd := n + payloadLen; buf.len() <= extensionPayloadEnd {
                        return n, fmt.Errorf("size %d < %d: %w", buf.len(), extensionPayloadEnd, errHeaderSizeInsufficientForExtension)
                    }

                    extension := Extension{id: extid, payload: buf[n : n+payloadLen]}
                    self.extensions = append(self.extensions, extension)
                    n += payloadLen
                }
            } else {
                // RFC3550 Extension
                let extension = Extension{ id: 0, payload: buf[n:extensionEnd] };
                self.extensions = append(self.extensions, extension)
                n += self.extensions[0].payload.len();
            }
        }

        Ok(n)
    }
}

impl Packet {
    /// Unmarshal parses the passed byte slice and stores the result in the Packet.
    pub fn unmarshal(buf []byte) error {
        n, err := p.Header.Unmarshal(buf)
        if err != nil {
            return err
        }

        end := buf.len()
        if p.Header.Padding {
            if end <= n {
                return errTooSmall
            }
            p.PaddingSize = buf[end-1]
            end -= int(p.PaddingSize)
        } else {
            p.PaddingSize = 0
        }
        if end < n {
            return errTooSmall
        }

        p.Payload = buf[n:end]

        return nil
    }
}

// Marshal serializes the header into bytes.
func (h Header) Marshal() (buf []byte, err error) {
    buf = make([]byte, h.MarshalSize())

    n, err := h.MarshalTo(buf)
    if err != nil {
        return nil, err
    }

    return buf[:n], nil
}

// MarshalTo serializes the header and writes to the buffer.
func (h Header) MarshalTo(buf []byte) (n int, err error) { //nolint:cyclop
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

    size := h.MarshalSize()
    if size > buf.len() {
        return 0, io.ErrShortBuffer
    }

    // The first byte contains the version, padding bit, extension bit,
    // and csrc size.
    buf[0] = (h.Version << VERSION_SHIFT) | uint8(len(self.csrc)) // nolint: gosec // G115
    if h.Padding {
        buf[0] |= 1 << PADDING_SHIFT;
    }

    if self.extension {
        buf[0] |= 1 << EXTENSION_SHIFT;
    }

    // The second byte contains the marker bit and payload type.
    buf[1] = self.payload_type
    if self.marker {
        buf[1] |= 1 << MARKER_SHIFT
    }

    binary.BigEndian.PutUint16(buf[2:4], self.sequence_number);
    binary.BigEndian.PutUint32(buf[4:8], self.timestamp)
    binary.BigEndian.PutUint32(buf[8:12], self.ssrc)

    n = 12
    for _, csrc := range self.csrc {
        binary.BigEndian.PutUint32(buf[n:n+4], csrc)
        n += 4
    }

    if self.extension {
        extHeaderPos := n
        binary.BigEndian.PutUint16(buf[n+0:n+2], self.extension_profile)
        n += 4
        startExtensionsPos := n

        switch self.extension_profile {
        // RFC 8285 RTP One Byte Header Extension
        case EXTENSION_PROFILE_ONE_BYTE:
            for _, extension := range self.extensions {
                buf[n] = extension.id<<4 | (uint8(len(extension.payload)) - 1) // nolint: gosec // G115
                n++
                n += copy(buf[n:], extension.payload)
            }
        // RFC 8285 RTP Two Byte Header Extension
        case EXTENSION_PROFILE_TWO_BYTE:
            for _, extension := range self.extensions {
                buf[n] = extension.id
                n++
                buf[n] = uint8(len(extension.payload)) // nolint: gosec // G115
                n++
                n += copy(buf[n:], extension.payload)
            }
        default: // RFC3550 Extension
            extlen := len(self.extensions[0].payload)
            if extlen%4 != 0 {
                // the payload must be in 32-bit words.
                return 0, io.ErrShortBuffer
            }
            n += copy(buf[n:], self.extensions[0].payload)
        }

        // calculate extensions size and round to 4 bytes boundaries
        extSize := n - startExtensionsPos
        roundedExtSize := ((extSize + 3) / 4) * 4

        // nolint: gosec // G115 false positive
        binary.BigEndian.PutUint16(buf[extHeaderPos+2:extHeaderPos+4], uint16(roundedExtSize/4))

        // add padding to reach 4 bytes boundaries
        for i := 0; i < roundedExtSize-extSize; i++ {
            buf[n] = 0
            n++
        }
    }

    return n, nil
}

impl Header {
    /// MarshalSize returns the size of the header once marshaled.
    pub fn marshal_size(&self) -> int {
        // NOTE: Be careful to match the MarshalTo() method.
        let size = 12 + (self.csrc.len() * CSRC_LENGTH);

        if self.extension {
            let mut ext_size = 4;

            match self.extension_profile {
                // RFC 8285 RTP One Byte Header Extension
                EXTENSION_PROFILE_ONE_BYTE => {
                    for _, extension in &self.extensions {
                        ext_size += 1 + len(extension.payload)
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
    pub fn set_extension(&mut self, id: u8, payload: &[u8] /* TODO(rinarakaki) or Vec<u8> */) -> Result<(), ?> {
        if self.extension {
            match self.extension_profile {
                // RFC 8285 RTP One Byte Header Extension
                EXTENSION_PROFILE_ONE_BYTE => {
                    if id < 1 || id > 14 {
                        return fmt.Errorf("%w actual(%d)", errRFC8285OneByteHeaderIDRange, id);
                    }
                    if len(payload) > 16 {
                        return fmt.Errorf("%w actual(%d)", errRFC8285OneByteHeaderSize, len(payload));
                    }
                }
                // RFC 8285 RTP Two Byte Header Extension
                EXTENSION_PROFILE_TWO_BYTE => {
                    if id < 1 {
                        return fmt.Errorf("%w actual(%d)", errRFC8285TwoByteHeaderIDRange, id);
                    }
                    if len(payload) > 255 {
                        return fmt.Errorf("%w actual(%d)", errRFC8285TwoByteHeaderSize, len(payload));
                    }
                }
                // RFC3550 Extension
                _ => {
                    if id != 0 {
                        return fmt.Errorf("%w actual(%d)", errRFC3550HeaderIDRange, id);
                    }
                }
            }

            // Update existing if it exists else add new extension
            for extension in &mut self.extensions {
                if extension.id == id {
                    extensions.payload = payload;

                    return nil;
                }
            }

            self.extensions.push(Extension { id, payload });

            return nil;
        }

        // No existing header extensions
        self.extension = true;

        let payload_len = payload.len();
        if payload_len <= 16 {
            self.extension_profile = EXTENSION_PROFILE_ONE_BYTE;
        } else if payload_len > 16 && payload_len < 256 {
            self.extension_profile = EXTENSION_PROFILE_TWO_BYTE;
        }

        self.extensions.push(Extension{ id, payload });

        return nil
    }
}

// GetExtensionIDs returns an extension id array.
func (h *Header) GetExtensionIDs() []uint8 {
    if !self.extension {
        return nil
    }

    if len(self.extensions) == 0 {
        return nil
    }

    ids := make([]uint8, 0, len(self.extensions))
    for _, extension := range self.extensions {
        ids = append(ids, extension.id)
    }

    return ids
}

// GetExtension returns an RTP header extension.
func (h *Header) GetExtension(id uint8) []byte {
    if !self.extension {
        return nil
    }
    for _, extension := range self.extensions {
        if extension.id == id {
            return extension.payload
        }
    }

    return nil
}

// DelExtension Removes an RTP Header extension.
func (h *Header) DelExtension(id uint8) error {
    if !self.extension {
        return errHeaderExtensionsNotEnabled
    }
    for i, extension := range self.extensions {
        if extension.id == id {
            self.extensions = append(self.extensions[:i], self.extensions[i+1:]...)

            return nil
        }
    }

    return errHeaderExtensionNotFound
}

// Marshal serializes the packet into bytes.
func (p Packet) Marshal() (buf []byte, err error) {
    buf = make([]byte, p.MarshalSize())

    n, err := p.MarshalTo(buf)
    if err != nil {
        return nil, err
    }

    return buf[:n], nil
}

// MarshalTo serializes the packet and writes to the buffer.
func (p *Packet) MarshalTo(buf []byte) (n int, err error) {
    if p.Header.Padding && p.PaddingSize == 0 {
        return 0, errInvalidRTPPadding
    }

    n, err = p.Header.MarshalTo(buf)
    if err != nil {
        return 0, err
    }

    // Make sure the buffer is large enough to hold the packet.
    if n+len(p.Payload)+int(p.PaddingSize) > buf.len() {
        return 0, io.ErrShortBuffer
    }

    m := copy(buf[n:], p.Payload)

    if p.Header.Padding {
        buf[n+m+int(p.PaddingSize-1)] = p.PaddingSize
    }

    return n + m + int(p.PaddingSize), nil
}

// MarshalSize returns the size of the packet once marshaled.
func (p Packet) MarshalSize() int {
    return p.Header.MarshalSize() + len(p.Payload) + int(p.PaddingSize)
}

// Clone returns a deep copy of p.
func (p Packet) Clone() *Packet {
    clone := &Packet{}
    clone.Header = p.Header.Clone()
    if p.Payload != nil {
        clone.Payload = make([]byte, len(p.Payload))
        copy(clone.Payload, p.Payload)
    }
    clone.PaddingSize = p.PaddingSize

    return clone
}

// Clone returns a deep copy h.
func (h Header) Clone() Header {
    clone := h
    if self.csrc != nil {
        clone.CSRC = make([]uint32, len(self.csrc))
        copy(clone.CSRC, self.csrc)
    }
    if self.extensions != nil {
        ext := make([]Extension, len(self.extensions))
        for i, e := range self.extensions {
            ext[i] = e
            if e.payload != nil {
                ext[i].payload = make([]byte, len(e.payload))
                copy(ext[i].payload, e.payload)
            }
        }
        clone.Extensions = ext
    }

    return clone
}

