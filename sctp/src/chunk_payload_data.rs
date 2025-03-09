// https://github.com/pion/sctp/blob/bf53986cb1bbb4f7a71552bdd47f3e5a9802526a/chunk_payload_data.go

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

import (
    "encoding/binary"
    "errors"
    "fmt"
    "time"
)

use crate::chunkheader::ChunkHeader;

/*
ChunkPayloadData represents an SCTP Chunk of type DATA

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Type = 0    | Reserved|U|B|E|    Length                     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                              TSN                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Stream Identifier S      |   Stream Sequence Number n    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  Payload Protocol Identifier                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                 User Data (seq n of Stream S)                 |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

An unfragmented user message shall have both the B and E bits set to
'1'.  Setting both B and E bits to '0' indicates a middle fragment of
a multi-fragment user message, as summarized in the following table:

       B E                  Description
    ============================================================
    |  1 0 | First piece of a fragmented user message          |
    +----------------------------------------------------------+
    |  0 0 | Middle piece of a fragmented user message         |
    +----------------------------------------------------------+
    |  0 1 | Last piece of a fragmented user message           |
    +----------------------------------------------------------+
    |  1 1 | Unfragmented message                              |
    ============================================================
    |             Table 1: Fragment Description Flags          |
    ============================================================
*/
pub(crate) struct ChunkPayloadData {
    chunk_header: ChunkHeader,

    unordered: bool,
    beginningFragment bool
    beginning_fragment: bool,
    immediate_sack: bool,

    tsn: u32,
    stream_identifier: u16,
    stream_sequence_number: u16,
    payload_type: PayloadProtocolIdentifier,
    user_data: Vec<u8>,

    // Whether this data chunk was acknowledged (received by peer)
    acked: bool,
    miss_indicator: u32,

    // Partial-reliability parameters used only by sender
    since: Instant,
    n_sent: u32, // number of transmission made for this chunk
    _abandoned: bool,
    _all_inflight: bool, // valid only with the first fragment

    // Retransmission flag set when T1-RTX timeout occurred and this
    // chunk is still in the inflight queue
    retransmit: bool,

    head: Option<Arc<Mutex<ChunkPayloadData>>>, // link to the head of the fragment
}

const (
    payloadDataEndingFragmentBitmask   = 1
    payloadDataBeginingFragmentBitmask = 2
    payloadDataUnorderedBitmask        = 4
    payloadDataImmediateSACK           = 8

    payloadDataHeaderSize = 12
)

/// PayloadProtocolIdentifier is an enum for DataChannel payload types.
/// https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25
#[repr(u32)]
pub enum PayloadProtocolIdentifier {
    Unknown = 0,
    WebRTCDCEP = 50,
    WebRTCString = 51,
    WebRTCBinary = 53,
    WebRTCStringEmpty = 56,
    WebRTCBinaryEmpty = 57,
}

// Data chunk errors.
var (
    ErrChunkPayloadSmall = errors.New("packet is smaller than the header size")
)

func (p PayloadProtocolIdentifier) String() string {
    switch p {
    case PayloadTypeWebRTCDCEP:
        return "WebRTC DCEP"
    case PayloadTypeWebRTCString:
        return "WebRTC String"
    case PayloadTypeWebRTCBinary:
        return "WebRTC Binary"
    case PayloadTypeWebRTCStringEmpty:
        return "WebRTC String (Empty)"
    case PayloadTypeWebRTCBinaryEmpty:
        return "WebRTC Binary (Empty)"
    default:
        return fmt.Sprintf("Unknown Payload Protocol Identifier: %d", p)
    }
}

func (p *ChunkPayloadData) unmarshal(raw []byte) error {
    if err := p.chunkHeader.unmarshal(raw); err != nil {
        return err
    }

    p.immediateSack = p.flags&payloadDataImmediateSACK != 0
    p.unordered = p.flags&payloadDataUnorderedBitmask != 0
    p.beginningFragment = p.flags&payloadDataBeginingFragmentBitmask != 0
    p.endingFragment = p.flags&payloadDataEndingFragmentBitmask != 0

    if len(p.raw) < payloadDataHeaderSize {
        return ErrChunkPayloadSmall
    }
    p.tsn = binary.BigEndian.Uint32(p.raw[0:])
    p.streamIdentifier = binary.BigEndian.Uint16(p.raw[4:])
    p.streamSequenceNumber = binary.BigEndian.Uint16(p.raw[6:])
    p.payloadType = PayloadProtocolIdentifier(binary.BigEndian.Uint32(p.raw[8:]))
    p.userData = p.raw[payloadDataHeaderSize:]

    return nil
}

func (p *ChunkPayloadData) marshal() ([]byte, error) {
    payRaw := make([]byte, payloadDataHeaderSize+len(p.userData))

    binary.BigEndian.PutUint32(payRaw[0:], p.tsn)
    binary.BigEndian.PutUint16(payRaw[4:], p.streamIdentifier)
    binary.BigEndian.PutUint16(payRaw[6:], p.streamSequenceNumber)
    binary.BigEndian.PutUint32(payRaw[8:], uint32(p.payloadType))
    copy(payRaw[payloadDataHeaderSize:], p.userData)

    flags := uint8(0)
    if p.endingFragment {
        flags = 1
    }
    if p.beginningFragment {
        flags |= 1 << 1
    }
    if p.unordered {
        flags |= 1 << 2
    }
    if p.immediateSack {
        flags |= 1 << 3
    }

    p.chunkHeader.flags = flags
    p.chunkHeader.typ = ctPayloadData
    p.chunkHeader.raw = payRaw

    return p.chunkHeader.marshal()
}

func (p *ChunkPayloadData) check() (abort bool, err error) {
    return false, nil
}

// String makes ChunkPayloadData printable.
func (p *ChunkPayloadData) String() string {
    return fmt.Sprintf("%s\n%d", p.chunkHeader, p.tsn)
}

func (p *ChunkPayloadData) abandoned() bool {
    if p.head != nil {
        return p.head._abandoned && p.head._allInflight
    }

    return p._abandoned && p._allInflight
}

func (p *ChunkPayloadData) setAbandoned(abandoned bool) {
    if p.head != nil {
        p.head._abandoned = abandoned

        return
    }
    p._abandoned = abandoned
}

func (p *ChunkPayloadData) setAllInflight() {
    if p.endingFragment {
        if p.head != nil {
            p.head._allInflight = true
        } else {
            p._allInflight = true
        }
    }
}

func (p *ChunkPayloadData) isFragmented() bool {
    return !(p.head == nil && p.beginningFragment && p.endingFragment)
}
