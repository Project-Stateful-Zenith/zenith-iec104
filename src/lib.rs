//! An implementation of IEC 60870-5-104 ("IEC 104"), the telecontrol protocol
//! that carries IEC 60870-5-101 application data over TCP. It covers both
//! roles: the controlling station (the master) and the controlled station (the
//! outstation). The crate has no dependencies.
//!
//! # Sans-IO
//!
//! The crate never opens a socket, reads a clock or spawns a thread. You feed
//! it the octets you received and the current time, and it returns what to do:
//! frames to send, data to hand to the application, a connection to close. Your
//! code performs those actions. This keeps every procedure testable without a
//! network or a real clock. The `examples/` directory has a complete master and
//! outstation over blocking TCP; the `iec104-tokio` crate in the same workspace
//! builds async drivers on this one, and on them a client and a server that
//! run the procedures; `iec104-tls` adds TLS.
//!
//! # The three layers
//!
//! A received TCP stream passes through three layers, and a frame you send
//! passes through them in reverse:
//!
//! 1. **Framing.** [`framed`] cuts the byte stream into whole frames (APDUs),
//!    and [`apci`] decodes the frame header: its start octet, its length and its
//!    control field. The control field says which of the three frame formats it
//!    is: I (numbered, carries application data), S (acknowledgement only) or U
//!    (the STARTDT, STOPDT and TESTFR control functions).
//! 2. **Link.** [`link`] is the state machine of one TCP connection: starting
//!    and stopping data transfer, keep-alive tests, and the reaction to protocol
//!    errors. [`seq`] numbers the I-frames and tracks which ones the peer has
//!    acknowledged, [`timers`] decides when the time-outs t0 to t3 are due, and
//!    [`params`] holds their values with the standard's defaults. Above one
//!    connection, [`manager`] runs several stations with reconnection, and
//!    [`redundancy`] runs one station's redundant connections.
//! 3. **Application.** [`asdu`] encodes and decodes the application data unit
//!    (ASDU) that an I-frame carries: its header, type identification, cause of
//!    transmission and information objects. [`dispatch`] says which procedure a
//!    received ASDU belongs to, and each procedure module runs one exchange of
//!    the standard, in both roles.
//!
//! # Module map
//!
//! | Module | What it does |
//! | --- | --- |
//! | [`framed`] | Byte stream to whole frames; an octet other than the start octet where a frame begins is reported |
//! | [`apci`] | Frame header codec: I, S and U formats |
//! | [`link`] | Connection state machine: STARTDT/STOPDT, TESTFR, error reactions |
//! | [`seq`] | Sequence numbers, acknowledgements and the k/w window |
//! | [`timers`] | Scheduling of the time-outs t0 to t3 |
//! | [`params`] | Link parameters (k, w, t0 to t3, port) and their admissible ranges |
//! | [`manager`] | Several stations, each with its own connection and reconnection |
//! | [`redundancy`] | Redundant connections to one station (clause 10) |
//! | [`asdu`] | ASDU codec: header, types, causes, information elements, address sizes; a whole ASDU decoded into typed objects, and its monitored values as [`asdu::Point`]s ([`asdu::Objects::points`]); `CP56Time2a` to and from Unix time and `SystemTime` |
//! | [`dispatch`] | Routing a received ASDU to the procedure that owns it |
//! | [`init`] | Station initialisation (end of initialisation) |
//! | [`gi`] | General interrogation |
//! | [`ci`] | Counter interrogation |
//! | [`cs`] | Clock synchronisation, and the time tags' invalid mark ([`cs::TimeValidity`]) |
//! | [`ct`] | Command transmission |
//! | [`rd`] | Read command (data acquisition by polling) |
//! | [`pm`] | Parameter loading |
//! | [`ts`] | Test procedure |
//! | [`tx`] | Cyclic transmission, background scan and acquisition of events; the send order of 5-101 Table 16 ([`tx::respond_priority`]) |
//! | [`ft`] | File transfer; [`ft::receive`] keeps the receiving side's session |
//! | [`interop`] | The interoperability profile of clause 9: which options a system uses |
//! | [`diag`] | One-line, human-readable descriptions of frames for logs |
//!
//! # Example
//!
//! Each procedure is a value you feed received ASDUs to; it returns what the
//! ASDU meant and the frames to answer with.
//!
//! ```
//! use iec104::asdu::{Header, Known};
//! use iec104::dispatch::{route, Route};
//! use iec104::gi::{Interrogation, Reaction, Scope, SecondActivation};
//!
//! // The controlling station builds a station interrogation: an ASDU to send
//! // as an I-frame.
//! let mut gi = Interrogation::controlling(SecondActivation::Locked, 1, 0);
//! let request = gi.request(Scope::Station).unwrap();
//! assert_eq!(route(&Header::parse(&request).unwrap()), Route::Interrogation);
//!
//! // Every ASDU that comes back goes to the procedure that owns it.
//! let mut confirmation = request.clone();
//! confirmation[2] = 7; // cause 7: activation confirmation
//! let outcome = gi.on_response(&confirmation, &Known::EVERYTHING).unwrap();
//! assert_eq!(
//!     outcome.reaction,
//!     Reaction::ActivationConfirmed { scope: Scope::Station, negative: false }
//! );
//! ```
//!
//! # Where the rules come from
//!
//! The module documentation cites the clause behind each rule. "5-104" or
//! "104" is IEC 60870-5-104:2006, "5-101" or "101" is IEC 60870-5-101:2003,
//! and "604" is IEC TS 60870-5-604:2016, the conformance test specification.

pub mod apci;
pub mod asdu;
pub mod ci;
pub mod cs;
pub mod ct;
pub mod diag;
pub mod dispatch;
pub mod framed;
pub mod ft;
pub mod gi;
pub mod init;
pub mod interop;
pub mod link;
pub mod manager;
pub mod params;
pub mod pm;
pub mod rd;
pub mod redundancy;
pub mod seq;
pub mod timers;
pub mod ts;
pub mod tx;
