// https://github.com/pion/datachannel/blob/15a4d100b9b29b106edebbbdc4e8e0dd9941d0de/message_channel_open.go
// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

/*
channelOpen represents a DATA_CHANNEL_OPEN Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Message Type |  Channel Type |            Priority           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Reliability Parameter                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Label Length          |       Protocol Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                             Label                             |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                            Protocol                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
.
*/
pub(crate) struct ChannelOpen {
    pub channel_type: ChannelType,
    pub priority: u16,
    pub reliability_parameter: u32,

    pub label: Vec<u8>,
    pub protocol: Vec<u8>,
}

const CHANNEL_OPEN_HEADER_LENGTH: usize = 12;

/// ChannelType determines the reliability of the WebRTC DataChannel.
pub enum ChannelType {
    /// ChannelTypeReliable determines the Data Channel provides a
    /// reliable in-order bi-directional communication.
    Reliable = 0x00,
    /// ChannelTypeReliableUnordered determines the Data Channel
    /// provides a reliable unordered bi-directional communication.
    ReliableUnordered = 0x80,
    /// ChannelTypePartialReliableRexmit determines the Data Channel
    /// provides a partially-reliable in-order bi-directional communication.
    /// User messages will not be retransmitted more times than specified in the Reliability Parameter.
    PartialReliableRexmit = 0x01,
    /// ChannelTypePartialReliableRexmitUnordered determines
    /// the Data Channel provides a partial reliable unordered bi-directional communication.
    /// User messages will not be retransmitted more times than specified in the Reliability Parameter.
    PartialReliableRexmitUnordered = 0x81,
    /// ChannelTypePartialReliableTimed determines the Data Channel
    /// provides a partial reliable in-order bi-directional communication.
    /// User messages might not be transmitted or retransmitted after
    /// a specified life-time given in milli- seconds in the Reliability Parameter.
    /// This life-time starts when providing the user message to the protocol stack.
    PartialReliableTimed = 0x02,
    /// The Data Channel provides a partial reliable unordered bi-directional
    /// communication.  User messages might not be transmitted or retransmitted
    /// after a specified life-time given in milli- seconds in the Reliability Parameter.
    /// This life-time starts when providing the user message to the protocol stack.
    PartialReliableTimedUnordered = 0x82,
}

impl ChannelType {
    pub fn string(&self) -> &str {
        match self {
            ChannelType::Reliable | ChannelType::ReliableUnordered => "ReliableUnordered",
            ChannelType::PartialReliableRexmit => "PartialReliableRexmit",
            ChannelType::PartialReliableRexmitUnordered => "PartialReliableRexmitUnordered",
            ChannelType::PartialReliableTimed => "PartialReliableTimed",
            ChannelType::PartialReliableTimedUnordered => "PartialReliableTimedUnordered",
            _ => "Unknown",
        }
    }
}

/// ChannelPriority enums.
#[repr(u16)]
pub enum ChannelPriority {
    BelowNormal = 128,
    Normal = 256,
    High = 512,
    ExtraHigh = 1024,
}

impl ChannelOpen {
    /// Marshal returns raw bytes for the given message.
    pub fn marshal(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let label_length = self.label.len();
        let protocol_length = self.protocol.len();

        let total_len = CHANNEL_OPEN_HEADER_LENGTH + label_length + protocol_length;
        let mut raw = vec![0u8; total_len];

        raw[0] = DataChannelMessageType::Open as u8;
        // Second byte: channel type
        raw[1] = match self.channel_type {
            ChannelType::Unknown(value) => value,
            x => x as u8,
        };
        // Next 2 bytes: priority
        raw[2..4].copy_from_slice(&self.priority.to_be_bytes());
        // Next 4 bytes: reliability parameter
        raw[4..8].copy_from_slice(&self.reliability_parameter.to_be_bytes());
        // Next 2 bytes: label length
        raw[8..10].copy_from_slice(&(label_length as u16).to_be_bytes());
        // Next 2 bytes: protocol length
        raw[10..12].copy_from_slice(&(protocol_length as u16).to_be_bytes());

        // Label bytes
        raw[CHANNEL_OPEN_HEADER_LENGTH..CHANNEL_OPEN_HEADER_LENGTH + label_length]
            .copy_from_slice(&self.label);

        // Protocol bytes
        let protocol_offset = CHANNEL_OPEN_HEADER_LENGTH + label_length;
        raw[protocol_offset..protocol_offset + protocol_length]
            .copy_from_slice(&self.protocol);

        raw
    }
}
// Marshal returns raw bytes for the given message.
func (c *channelOpen) Marshal() ([]byte, error) {
    labelLength := len(c.Label)
    protocolLength := len(c.Protocol)

    totalLen := CHANNEL_OPEN_HEADER_LENGTH + labelLength + protocolLength
    raw := make([]byte, totalLen)

    raw[0] = uint8(dataChannelOpen)
    raw[1] = byte(c.ChannelType)
    binary.BigEndian.PutUint16(raw[2:], c.Priority)
    binary.BigEndian.PutUint32(raw[4:], c.ReliabilityParameter)
    binary.BigEndian.PutUint16(raw[8:], uint16(labelLength))     //nolint:gosec //G115
    binary.BigEndian.PutUint16(raw[10:], uint16(protocolLength)) //nolint:gosec //G115
    endLabel := CHANNEL_OPEN_HEADER_LENGTH + labelLength
    copy(raw[CHANNEL_OPEN_HEADER_LENGTH:endLabel], c.Label)
    copy(raw[endLabel:endLabel+protocolLength], c.Protocol)

    return raw, nil
}

// Unmarshal populates the struct with the given raw data.
func (c *channelOpen) Unmarshal(raw []byte) error {
    if len(raw) < CHANNEL_OPEN_HEADER_LENGTH {
        return fmt.Errorf("%w expected(%d) actual(%d)", ErrExpectedAndActualLengthMismatch, CHANNEL_OPEN_HEADER_LENGTH, len(raw))
    }
    c.ChannelType = ChannelType(raw[1])
    c.Priority = binary.BigEndian.Uint16(raw[2:])
    c.ReliabilityParameter = binary.BigEndian.Uint32(raw[4:])

    labelLength := binary.BigEndian.Uint16(raw[8:])
    protocolLength := binary.BigEndian.Uint16(raw[10:])

    if expectedLen := CHANNEL_OPEN_HEADER_LENGTH + int(labelLength) + int(protocolLength); len(raw) != expectedLen {
        return fmt.Errorf("%w expected(%d) actual(%d)", ErrExpectedAndActualLengthMismatch, expectedLen, len(raw))
    }

    c.Label = raw[CHANNEL_OPEN_HEADER_LENGTH : CHANNEL_OPEN_HEADER_LENGTH+labelLength]
    c.Protocol = raw[CHANNEL_OPEN_HEADER_LENGTH+labelLength : CHANNEL_OPEN_HEADER_LENGTH+labelLength+protocolLength]

    return nil
}

func (c channelOpen) String() string {
    return fmt.Sprintf(
        "Open ChannelType(%s) Priority(%v) ReliabilityParameter(%d) Label(%s) Protocol(%s)",
        c.ChannelType, c.Priority, c.ReliabilityParameter, string(c.Label), string(c.Protocol),
    )
}
