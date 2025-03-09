// https://github.com/pion/datachannel/blob/15a4d100b9b29b106edebbbdc4e8e0dd9941d0de/message.go

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

use crate::message_channel_ack::ChannelAck;
use crate::message_channel_open::ChannelOpen;

/// message is a parsed DataChannel message.
pub trait Message {
    fn marshal(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn unmarshal(&mut self, _: &[u8]) -> Result<(), Box<dyn std::error::Error>>;
    fn string(&self) -> String;
}

/// messageType is the first byte in a DataChannel message that specifies type.
pub(crate) enum MessageType {
    DataChannelAck  = 0x02,
    DataChannelOpen = 0x03,
}

impl MessageType {
    pub fn string(&self) -> String {
        match self {
            MessageType::DataChannelAck => "DataChannelAck".to_string(),
            MessageType::DataChannelOpen => "DataChannelOpen".to_string(),
        }
    }
}

/// parse accepts raw input and returns a DataChannel message.
pub fn parse(raw: &[u8]) -> Result<Box<dyn Message>, Box<dyn std::error::Error>> {
    if raw.is_empty() {
        return Err(DataChannelError::MessageTooShort.into());
    }

    let msg_type = MessageType::try_from(raw[0])?;
    let mut msg: Box<dyn Message> = match msg_type {
        MessageType::DataChannelOpen => Box::new(ChannelOpen),
        MessageType::DataChannelAck  => Box::new(ChannelAck),
    };

    msg.unmarshal(raw)?;

    Ok(msg)
}

/// parseExpectDataChannelOpen parses a DataChannelOpen message
/// or throws an error.
pub fn parse_expect_data_channel_open(raw: &[u8]) -> Result<ChannelOpen, Box<dyn std::error::Error>> {
    if raw.is_empty() {
        return Err(ErrDataChannelMessageTooShort);
    }

    let actual_type = MessageType::try_from(raw[0])?;
    if actual_type != MessageType::DataChannelOpen {
        return Err(Box::new(format!(
            "%w expected(%s) actual(%s)",
            ErrUnexpectedDataChannelType,
            actual_type,
            MessageType::DataChannelOpen
        )));
    }

    let mut msg = ChannelOpen;
    msg.unmarshal(raw)?;

    Ok(msg)
}

/// TryMarshalUnmarshal attempts to marshal and unmarshal a message. Added for fuzzing.
pub fn try_marshal_unmarshal(raw: &[u8]) -> i32 {
    let message = match parse(raw) {
        Ok(m) => m,
        Err(_) => return 0,
    };

    if message.marshal().is_err() {
        return 0;
    }
    1
}
