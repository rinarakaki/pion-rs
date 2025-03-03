/// https://github.com/pion/rtp/blob/ee5524bed13b5f257ae7083ba4923001b59dfa59/error.go
// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum RtpError {
    HeaderSizeInsufficient,
    HeaderSizeInsufficientForExtension,
    TooSmall,
    HeaderExtensionsNotEnabled,
    HeaderExtensionNotFound,
    Rfc8285OneByteHeaderIdRange,
    Rfc8285OneByteHeaderSize,
    Rfc8285TwoByteHeaderIdRange,
    Rfc8285TwoByteHeaderSize,
    Rfc3550HeaderIdRange,
    InvalidRtpPadding,
}

impl fmt::Display for RtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtpError::HeaderSizeInsufficient => {
                write!(f, "RTP header size insufficient")
            }
            RtpError::HeaderSizeInsufficientForExtension => {
                write!(f, "RTP header size insufficient for extension")
            }
            RtpError::TooSmall => {
                write!(f, "buffer too small")
            }
            RtpError::HeaderExtensionsNotEnabled => {
                write!(f, "h.Extension not enabled")
            }
            RtpError::HeaderExtensionNotFound => {
                write!(f, "extension not found")
            }
            RtpError::Rfc8285OneByteHeaderIdRange => {
                write!(
                    f,
                    "header extension id must be between 1 and 14 \
                    for RFC 5285 one byte extensions"
                )
            }
            RtpError::Rfc8285OneByteHeaderSize => {
                write!(
                    f,
                    "header extension payload must be 16 bytes or less \
                    for RFC 5285 one byte extensions"
                )
            }
            RtpError::Rfc8285TwoByteHeaderIdRange => {
                write!(
                    f,
                    "header extension id must be between 1 and 255 \
                    for RFC 5285 two byte extensions"
                )
            }
            RtpError::Rfc8285TwoByteHeaderSize => {
                write!(
                    f,
                    "header extension payload must be 255 bytes or less \
                    for RFC 5285 two byte extensions"
                )
            }
            RtpError::Rfc3550HeaderIdRange => {
                write!(
                    f,
                    "header extension id must be 0 \
                    for non-RFC 5285 extensions"
                )
            }
            RtpError::InvalidRtpPadding => {
                write!(f, "invalid RTP padding")
            }
        }
    }
}

impl Error for RtpError {}
