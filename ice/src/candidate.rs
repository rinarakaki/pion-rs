// https://github.com/pion/ice/blob/f92d05f17c76e8ce326bad6cd9002f383b8d1415/candidate.go

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

import (
    "context"
    "net"
    "time"
)
use std::time::SystemTime;

const (
    receiveMTU             = 8192
    defaultLocalPreference = 65535

    // ComponentRTP indicates that the candidate is used for RTP.
    ComponentRTP uint16 = 1
    // ComponentRTCP indicates that the candidate is used for RTCP.
    ComponentRTCP
)

/// Candidate represents an ICE candidate.
pub trait Candidate {
    /// An arbitrary string used in the freezing algorithm to
    /// group similar candidates.  It is the same for two candidates that
    /// have the same type, base IP address, protocol (UDP, TCP, etc.),
    /// and STUN or TURN server.
    fn foundation(&self) -> &str;

    /// ID is a unique identifier for just this candidate
    /// Unlike the foundation this is different for each candidate
    fn id(&self) -> &str;

    /// A component is a piece of a data stream.
    /// An example is one for RTP, and one for RTCP
    fn component(&self) -> u16;
    fn set_component(&mut self, component: u16);

    /// The last time this candidate received traffic
    fn last_received(&self) -> SystemTime;

    /// The last time this candidate sent traffic
    fn last_sent(&self) -> SystemTime;

    NetworkType() NetworkType
    Address() string
    Port() int

    Priority() uint32

    /// A transport address related to a
    ///  candidate, which is useful for diagnostics and other purposes
    RelatedAddress() *CandidateRelatedAddress

    /// Extensions returns a copy of all extension attributes associated with the ICECandidate.
    /// In the order of insertion, *(key value).
    /// Extension attributes are defined in RFC 5245, Section 15.1:
    /// https://datatracker.ietf.org/doc/html/rfc5245#section-15.1
    ///.
    Extensions() []CandidateExtension
    /// GetExtension returns the value of the extension attribute associated with the ICECandidate.
    /// Extension attributes are defined in RFC 5245, Section 15.1:
    /// https://datatracker.ietf.org/doc/html/rfc5245#section-15.1
    ///.
    GetExtension(key string) (value CandidateExtension, ok bool)
    /// AddExtension adds an extension attribute to the ICECandidate.
    /// If an extension with the same key already exists, it will be overwritten.
    /// Extension attributes are defined in RFC 5245, Section 15.1:
    AddExtension(extension CandidateExtension) error
    /// RemoveExtension removes an extension attribute from the ICECandidate.
    /// Extension attributes are defined in RFC 5245, Section 15.1:
    RemoveExtension(key string) (ok bool)

    String() string
    Type() CandidateType
    TCPType() TCPType

    Equal(other Candidate) bool

    /// DeepEqual same as Equal, But it also compares the candidate extensions.
    DeepEqual(other Candidate) bool

    Marshal() string

    addr() net.Addr
    filterForLocationTracking() bool
    agent() *Agent
    context() context.Context

    close() error
    copy() (Candidate, error)
    seen(outbound bool)
    start(a *Agent, conn net.PacketConn, initializedCh <-chan struct{})
    writeTo(raw []byte, dst Candidate) (int, error)
}
