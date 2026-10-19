//! Redundancy groups: IEC 60870-5-104:2006 clause 10.
//!
//! This module implements
//! the model and the seven general rules of 10.1/10.2, the station
//! initialisation of 10.3 (the controlling station) and 10.4 (the controlled
//! station), the user-data routing with the t1-driven switchover of 10.5 and
//! 10.6, and the two state-transition diagrams of 10.7 with the close rule, the
//! manual switchover and the asymmetric `t1`.
//!
//! # Driving a group
//!
//! Use the timer-aware entry points: [`RedundancyGroup::tick`] with the
//! caller's clock (for a controlling group it asks for each member that is
//! down to be dialled, and it reacts to every expired timer; a t1 on the
//! started connection is the switchover),
//! [`RedundancyGroup::on_connection_established`] /
//! [`RedundancyGroup::on_connection_lost`] for the sockets, and the `_at`
//! methods ([`RedundancyGroup::on_frame_at`], [`RedundancyGroup::start_at`],
//! [`RedundancyGroup::send_user_data_at`], …) for the calls that have one.
//! [`RedundancyGroup::endinit`] has none: a caller that keeps t1 in step
//! builds the frame with [`end_of_initialisation`] and hands it to
//! [`RedundancyGroup::send_user_data_at`] itself. The `_at` methods keep
//! every member's [`Timers`] in step with the same
//! [`Supervisor`] wiring as [`crate::manager`], and
//! return [`Routed`] actions, one list per member, so each action reaches its
//! own socket. The plain methods below them do the same protocol work without
//! the timers and return one merged list.
//!
//! Clause 10 is **connection-level, not ASDU-level, and it changes nothing on
//! the wire.** A [`Session`] is one logical connection with one [`Timers`];
//! clause 10 describes what a *set* of them (a **redundancy group**) does
//! together. Every frame a group moves is a STARTDT/STOPDT of clause 5.3, a
//! TESTFR of clause 5.2 or a user ASDU of clause 7, so this module adds no
//! APDU, no ASDU and no cause. It coordinates members the caller already has,
//! and it grows no I/O loop: the sockets, the threads and the clock are the
//! caller's.
//!
//! # 10.1 and 10.2: the model (PDF page index 116 to 118, printed page 115 to 117)
//!
//! 10.2 defines a logical connection as a unique combination of the two
//! stations' IP-address/port-number pairs, and prints the fill-in box *"Number
//! N of redundancy group connections used"*: that N is the member count. The
//! seven general rules, verbatim with the clause's own numbering (rule 4's "is
//! be in started state" is the standard's text):
//!
//! | # | Rule |
//! | --- | --- |
//! | 1 | "The controlling and controlled station shall be able to handle multiple (N) logical connections." |
//! | 2 | "The N logical connections represent one redundancy group." |
//! | 3 | "Only one logical connection is in the started state and sending/receiving user data at a time for one redundancy group." |
//! | 4 | "The controlling station decides which one of the N connections is be in started state." |
//! | 5 | "All logical connections of a redundancy group shall be supervised by test frames as described in 5.2." |
//! | 6 | "A redundancy group shall rely upon only one process image (database/event buffer)." |
//! | 7 | "If more than one controlling station need to access the same controlled station simultaneously, each controlling station must be assigned to a different redundancy group (process image)." |
//!
//! **Rule 3** is the invariant [`RedundancyGroup::route`] and
//! [`RedundancyGroup::send_user_data`] enforce and [`RedundancyGroup::start`]
//! brings about. **Rule 4** is the decision [`RedundancyGroup::select`] records
//! and `start` carries out, with [`RedundancyGroup::observe_startdt_act`] the
//! controlled station's positional half.
//!
//! The same page (index 118, printed 117) defines the started connection,
//! which [`RedundancyGroup::started`] names:
//!
//! > The logical connection which is enabled for user data transfer (started)
//! > at any time is defined to be the started connection, while the others are
//! > stopped connections. Selection of started connection is performed by means
//! > of the unnumbered control functions (U-frames) STARTDT/STOPDT as in 5.3 and
//! > according to the State transition diagrams in Figure 36 and Figure 37.
//!
//! Clause 5.3 is the selection mechanism
//! ([`Session::request_start`] and [`Session::request_stop`] send the acts),
//! clause 5.2's TESTFR is the supervision rule 5 asks for, and rule 4's
//! controlled-station half is positional rather than stateful:
//!
//! > The controlled station (station B) always understands the connection on
//! > which it last received a STARTDT_ACT as the started connection. It confirms
//! > the activation request by issuing a STARTDT_CON. The whole activation
//! > procedure is completed when the STARTDT_CON is received in the controlling
//! > station.
//!
//! Two more sentences of 10.2 belong to the group's state:
//!
//! > As stated in rule 4 above, the selection and switchover of the started
//! > connection is always initiated by the controlling station, and is managed by
//! > the transport interface or higher layers.
//!
//! > Send and receive counters on each connection within a redundancy group
//! > continue their functionality independently of the use of STARTDT/STOPDT.
//!
//! The counters live in [`crate::seq`], one per [`Session`], so the group does
//! not merge them: a member's counters move only when that member is fed.
//!
//! # 10.3 Initialisation of the controlling station (index 120, printed 119;
//! figure 32, index 122, printed 121)
//!
//! Verbatim:
//!
//! > After connection establishment, the stopped state is always default, and
//! > one of the connections (e.g. connection 1) is therefore changed from the
//! > stopped into the started state to enable user data transfer on this
//! > connection.
//!
//! > The ENDINIT.req (optional but recommended, Figures 32 and 33) may always
//! > be useful to advise the other station that the sending station is now
//! > ready to respond to an interrogation request. In case of initialisation of
//! > the controlling station, it is only issued if data in the reverse
//! > direction is defined.
//!
//! > The controlling station shall initiate a station interrogation procedure
//! > as soon as possible after the completion of making one of the connections
//! > in started state as shown in Figures 32 and 33.
//!
//! Figure 32 draws the TCP establishment, `U (STARTDT act)` / `U (STARTDT con)`
//! and the box `STARTED`, marks `A_ENDINIT.req`, `A_ENDINIT.ind` and
//! `<SEND=M_EI>` as `(optional)`, and ends in the box *"Following function:
//! Station interrogation"*. Its NOTE, verbatim:
//!
//! > The sequential interrelationship between the procedures on the connections
//! > is not fixed. For example, establishment of the connections may be started
//! > and go on in parallel.
//!
//! Three methods are that sequence, one call each:
//!
//! - [`RedundancyGroup::start`]: *"one of the connections … is therefore
//!   changed from the stopped into the started state"*, the STARTDT act of
//!   clause 5.3 (figure 37's `Start connection[]/Send STARTDT act`) through the
//!   member's own [`Session::request_start`]. Stopped is what
//!   [`Session::on_connection_established`] leaves behind, and establishment
//!   itself stays the caller's (clause 7.1, index 54). No order is imposed on
//!   the caller (the NOTE), so the connection that is up first may start first.
//! - [`RedundancyGroup::endinit`]: 10.3's `ENDINIT.req` as the caller's typed
//!   parameter [`EndInit`], issued only *"if data in the reverse direction is
//!   defined"*. The frame is [`end_of_initialisation`], this crate's one
//!   `M_EI_NA_1`.
//! - [`RedundancyGroup::follow_up`]: the station interrogation *"as soon as
//!   possible after the completion of making one of the connections in started
//!   state"*, as [`FollowUp::StationInterrogation`] once the started connection
//!   has reached [`State::Started`]. The caller performs the request it names
//!   with [`crate::gi::request`].
//!
//! # 10.4 Initialisation of the controlled station (index 124, printed 123;
//! figure 33, index 126, printed 125)
//!
//! Verbatim:
//!
//! > The sequential procedure for initialisation of the controlled station with
//! > N redundant connections within a single redundancy group is shown in
//! > Figure 33. After restart of the controlled station, the connections are
//! > established according to 7.1, but no user data is transmitted from the
//! > controlled station until started state on one connection is established.
//!
//! Figure 33 draws `active open` and `Timeout t0` per connection, then
//! `receive STARTDT` / `U (STARTDT act)` on the connection the controlling
//! station chose and the answer `U (STARTDT con)`, with the optional
//! `A_ENDINIT.req` / `<SEND=M_EI>` on the controlled side. Its NOTE is figure
//! 32's. 10.4 is the *passive* half of 10.3, and 10.2's positional sentence
//! above is its whole content, so the group gains one method for the frame the
//! caller received and nothing for the controlled station to decide:
//!
//! - [`RedundancyGroup::on_startdt_act`]: the frame is fed to the named
//!   member's own [`Session::on_frame`], which answers `U (STARTDT con)` and
//!   moves that connection to [`State::Started`] (clause 5.3), **and** the
//!   member is named the group's started connection. The session's actions are
//!   returned unchanged; the group invents no frame.
//!
//! **No user data leaves before such an act.** Before the peer's first
//! `STARTDT_ACT` the group names no started connection, and
//! [`RedundancyGroup::route`] and [`RedundancyGroup::send_user_data`] refuse
//! with [`GroupError::NoStartedConnection`]: that is 10.4's second sentence.
//! Monitoring data handed over once a connection is named, but before it may
//! carry data, waits in **that** connection's own clause 5.3 queue
//! ([`Session::queue_i_frame`]; index 38, printed 37: *"Any pending user data in
//! the controlled station is sent only after the STARTDT con."*), never in a
//! second member. Between a failure and the next naming the group holds it
//! itself ([`RedundancyGroup::held_user_data`]).
//!
//! 10.3's three procedures stay the controlling station's:
//! [`RedundancyGroup::start`], [`RedundancyGroup::endinit`] and
//! [`RedundancyGroup::follow_up`] refuse a controlled group with
//! [`GroupError::CannotSelect`], as [`RedundancyGroup::select`] does. 10.3's
//! ENDINIT condition is stated for the initialisation *"of the controlling
//! station"*, so the group issues no `ENDINIT.req` on a controlled station's
//! behalf: a caller that must announce a controlled station's restart builds
//! the frame itself ([`end_of_initialisation`]) and hands it over through
//! [`RedundancyGroup::send_user_data`] like every other ASDU of the group.
//!
//! # 10.5 User data from the controlling station (index 128, printed 127;
//! figure 34, index 130, printed 129)
//!
//! Verbatim:
//!
//! > If communication fails on the currently started connection (e.g.
//! > connection m) when the controlling station attempts to transmit user data
//! > (e.g. a command ASDU), a connection switchover will be performed
//! > (preferably automatic). The sequential procedure in this case is shown in
//! > Figure 34. It is up to the controlling station to select a new started
//! > connection. When transmission timeout (t1) has elapsed, one of the stopped
//! > connections (connection n) is started using the STARTDT function, The
//! > command is then directed to the new started connection, either by
//! > re-transmitting the ASDU on this connection or by terminating the ongoing
//! > application function and reinitiating it towards the new connection (it is
//! > left to the application if the ESDU is retransmitted). The failed
//! > connection is eventually closed by both sides, and reopening is regularly
//! > retried by the controlling station until the error has been corrected and
//! > the connection is re-established.
//!
//! > Any subsequent user data (e.g. events) are now transmitted on the new
//! > started connection.
//!
//! > A connection switchover will also be performed whenever a TESTFR_ACT on
//! > the started connection fails and hence reports a communication error on
//! > this connection.
//!
//! > Care shall be taken that data are not lost during a connection switchover,
//! > for example by doing a station interrogation procedure after a switchover
//! > has been performed.
//!
//! > The controlled station shall only acknowledge user data received on the
//! > connection on which it last received a STARTDT_ACT (the started
//! > connection).
//!
//! Figure 34 draws `COMMAND (example)` / `Timeout t1` / `U (STARTDT act)` /
//! `U (STARTDT con)` / `COMMAND (repeated)`, the close as `active close`, and
//! the retry as `Timeout t0`.
//!
//! Three methods are that subsection:
//!
//! - [`RedundancyGroup::on_timeout`] is the group's **switchover event**. A
//!   `Timer::T1` expiry on the started connection is *"when transmission
//!   timeout (t1) has elapsed"* (t1 being the timeout of a sent U-frame or
//!   I-frame, figures 17/18 NOTE 2), and a `TESTFR_ACT` that failed on that
//!   connection is the same expiry ([`Session::test_pending`]). The group
//!   starts *"one of the stopped connections"* with the STARTDT act of clause
//!   5.3 (through that member's own [`Session::request_start`]), names it the
//!   started connection, and reports [`Switchover::Automatic`]. The failed
//!   connection is closed by its own t1 reaction (figures 17/18's `Timeout
//!   t1[]/Active close`, returned in the same call). *"reopening is regularly
//!   retried by the controlling station"* is the caller's step, since the crate
//!   holds no socket; [`RedundancyGroup::tick`] asks for it.
//! - [`RedundancyGroup::retransmit_unconfirmed`] is *"it is left to the
//!   application if the ESDU is retransmitted"*. What a connection leaves
//!   behind is captured once, when it fails (an active close or a reported
//!   loss): the frames of its send buffer ([`Session::outstanding_frames`])
//!   followed by the group's mirror of its clause 5.3 queue
//!   ([`Member::queued_user_data`]). It is kept in [`Member::left_behind`],
//!   whatever happens to the member afterwards, until the application states
//!   its decision ([`Replay`]): replay it on the group's started connection,
//!   re-stamped with that connection's own `N(S)` (*"Each TCP connection …
//!   maintains its send- and receive counter"*, TS 60870-5-604 `5.4.13.10`,
//!   index 58, printed 57), or discard it. **Each captured ASDU is replayed at
//!   most once** ([`GroupError::AlreadyRetransmitted`]).
//! - [`RedundancyGroup::on_frame`]: *"The controlled station shall only
//!   acknowledge user data received on the connection on which it last received
//!   a `STARTDT_ACT` (the started connection)."* An I- or S-frame on any other
//!   connection is refused with [`GroupError::NotStartedConnection`] and is not
//!   fed to that connection's session, so nothing is acknowledged on it and its
//!   receive counter stays where it was. U-frames stay the connection's own on
//!   every member, because rule 5 supervises the stopped connections too.
//!
//! # 10.6 User data from the controlled station (index 132, printed 131;
//! figure 35, index 134, printed 133)
//!
//! Verbatim:
//!
//! > If communication fails on the started connection when the controlled
//! > station attempts to transmit user data (e.g. an event ASDU), the
//! > controlling station shall detect the failure and perform a connection
//! > switchover before the ASDU can be retransmitted on one of the previously
//! > stopped connections. A sequential procedure to illustrate this case is
//! > shown in Figure 35, with the use of asymmetric timeouts as explained in
//! > 10.7.
//!
//! > A STARTDT_ACT will eventually be received on one of the stopped connections
//! > (connection m) as a result of a timeout (t1) in the controlling station to
//! > a TESTFR frame on the currently started but failed connection. The selected
//! > stopped connection now becomes the new started connection, and the pending
//! > event is retransmitted on this connection.
//!
//! > In general, any unconfirmed user data will be retransmitted on the new
//! > started connection after a connection switchover has been performed,
//! > including potential unconfirmed ACTCONs or ACTTERMs.
//!
//! > The controlling station shall not acknowledge user data received on a
//! > connection which is not started.
//!
//! Figure 35 draws `Timeout t1 cancelled`, `Connection switchover`, `EVENT
//! (retransmitted)`, `Timeout t0`, `active close` and `Timeout t3`.
//!
//! The same three methods carry 10.6, read from the other side. A controlled
//! station detects the failure the same way (its own t1 expiring on the
//! started connection) but performs no switchover: rule 4 makes that the
//! peer's, so [`RedundancyGroup::on_timeout`] reports
//! [`Switchover::LeftToTheControllingStation`] and sends no STARTDT act. The
//! naming moves when the peer's act arrives on a stopped connection
//! ([`RedundancyGroup::on_startdt_act`]), and *"the pending event is
//! retransmitted on this connection"* is the same
//! [`RedundancyGroup::retransmit_unconfirmed`]. *"The controlling station shall
//! not acknowledge user data received on a connection which is not started"* is
//! [`RedundancyGroup::on_frame`]'s refusal: 10.5 states the rule for the
//! controlled station and 10.6 for the controlling one.
//!
//! # 10.7 State transition diagrams (index 136, printed 135; figure 36, index
//! 138, printed 137; figure 37, index 140, printed 139)
//!
//! Verbatim:
//!
//! > A timeout t1 in the controlling station on the started connection may
//! > automatically trigger the user application to issue a connection change
//! > request, and hence cause the start of a new (redundant) connection and an
//! > automatic connection switchover. Manual switchover is initiated by the user
//! > application either by a Stop on the started connection followed by a Start
//! > on another connection, or simply by issuing a connection change request.
//!
//! > Any connection that is not in the STOPPED state is immediately closed at
//! > the event of a Start on a new connection.
//!
//! > This means that asymmetric timeouts t1 can also be used (and t2
//! > correspondingly), i.e. shorter t1 in the controlling station than in the
//! > controlled station to reduce switchover time.
//!
//! > It should be possible to set the values of the timers t0 to t3 individually
//! > for each connection within a redundancy group.
//!
//! Both figures' NOTE 1 is *"Connection terminated means that there is no longer
//! any data exchange between TCP and the application protocol (CS104)."* and
//! their NOTE 2 *"t1 is the time out of a sent U-frame or I-frame."*
//!
//! **The boxes are the connection states, and they are [`State`]'s values, box
//! for box.** Figure 36 (controlled station, index 138) prints `STOPPED
//! connection`, `STARTED connection`, `Pending UNCONFIRMED STOPPED connection`
//! and the two terminals `Connection established` and `Connection terminated`;
//! figure 37 (controlling station, index 140) prints `STOPPED connection`,
//! `Pending STARTED connection`, `STARTED connection`, `Pending STOPPED
//! connection`, `Pending UNCONFIRMED STOPPED connection` and the same two
//! terminals. So [`State::Stopped`], [`State::PendingStarted`],
//! [`State::Started`], [`State::PendingStopped`],
//! [`State::PendingUnconfirmedStopped`] and [`State::Terminated`] are exactly
//! those boxes and the `Connection terminated` terminal (`Connection
//! established` is the entry into [`State::Stopped`] and has no value of its
//! own), read through [`Member::state`], and the group invents no state
//! of its own. A switchover, a start and a stop never leave two members in a
//! live state: one started connection is rule 3.
//!
//! The transitions this module carries out, with the figures' own labels:
//!
//! - **The close rule.** Figure 36's `STARTDT act[]/Close other not stopped
//!   connection(s)/Send STARTDT con` and figure 37's `Start connection[]/Send
//!   STARTDT act`: *"Any connection that is not in the STOPPED state is
//!   immediately closed at the event of a Start on a new connection."*
//!   [`RedundancyGroup::start`], [`RedundancyGroup::on_startdt_act`] and the
//!   automatic switchover of [`RedundancyGroup::on_timeout`] therefore return
//!   the close actions of every other member that is neither
//!   [`State::Stopped`] nor [`State::Terminated`], then the new connection's
//!   own frames (`on_timeout` puts the failed connection's own t1 reaction
//!   before both, and a repeated act on the connection already named closes
//!   nothing). Without it the connection that was
//!   started before would stay live: two started connections in one group.
//! - **The two stop transitions.** Figure 37's `Stop connection[no unconfirmed
//!   I-frames]/Send STOPDT act` and `Stop connection[unconfirmed I-frames]/Send
//!   STOPDT act`, plus the return `STOPDT con[]/` into `STOPPED connection`:
//!   [`RedundancyGroup::stop`] is the first of the manual switchover's two
//!   requests, and the member's own [`Session::request_stop`] chooses between
//!   the two transitions by its unconfirmed I-frames (clause 5.3).
//! - **The connection change.** Figure 37's `User application requests
//!   connection change[]/Active close` (the one transition only clause 10
//!   draws) and figure 36's incoming `Close initiated by another connection[]/`:
//!   [`RedundancyGroup::close`] is the active close of one connection, on either
//!   role (TS 60870-5-604 `5.4.13.20`, index 59, has *"either"* station close an
//!   inoperable member).
//! - **The close's reason.** The close rule and a connection change close
//!   through [`Session::close`], so the [`Action::ActiveClose`] they return
//!   names why: [`CLOSED_BY_START`] or [`CLOSED_BY_APPLICATION`]. The frames
//!   that go out (the pending acknowledgement first, figures 10/11's NOTE) are
//!   the same as for any active close.
//! - **The t1 and frame transitions** (`Timeout t1[]/Active close`,
//!   `S-frame[]/Active close` and `I-frame[]/Active close`) are the
//!   connection's own, [`Session::on_timeout`] and [`Session::on_frame`];
//!   [`RedundancyGroup::on_timeout`] carries the t1 one at group level, where it
//!   is also 10.5's switchover trigger. The `S-frame or I-frame [No unconfirmed
//!   I-frames]/` exit of figure 37's `Pending UNCONFIRMED STOPPED connection`
//!   into `Pending STOPPED connection` is clause 5.3's acknowledgement
//!   ([`Session::on_frame`] with an S-frame, or the N(R) of an I-frame).
//!
//! **Manual switchover is the two requests it is.** 10.2 (index 118): *"Manual
//! connection switchover can be performed by first issuing a `STOPDT_ACT` on the
//! currently started connection and then a `STARTDT_ACT` on the selected new
//! started connection. This will gracefully terminate data transfer on the first
//! connection before it is resumed on the new connection."* So it is
//! [`RedundancyGroup::stop`] on the started connection, the peer's `STOPDT con`
//! fed to that member, and then [`RedundancyGroup::start`] on the connection
//! that is to take over, not one `switch()` that hides the STOPDT. TS
//! 60870-5-604 `5.4.13.30` (indices 59–60, printed 58–59) is the case step by
//! step.
//!
//! **Asymmetric `t1` needs no code of its own.** Each member carries its own
//! [`Timers`] built from its own [`LinkParams`], so *"shorter t1 in the
//! controlling station than in the controlled station"* is a controlling group
//! configured with a shorter `t1` than the controlled one it talks to. The
//! switchover rides on whichever station's `t1` expires first, and a
//! controlled station does not switch over at all (rule 4), so the shorter
//! `t1` is what reduces the switchover time.
//!
//! # What the group is, and what it deliberately is not
//!
//! A [`RedundancyGroup`] is the membership and **which member is the started
//! connection**. Each member is a [`Member`]: one [`Session`] with its own
//! [`Timers`] and [`LinkParams`], which is how 10.7's per-connection timers
//! are expressed.
//!
//! - **No process image.** Rule 6 gives the group one database/event buffer for
//!   all N connections; that buffer is the *caller's*, exactly as it is for
//!   [`crate::rd`] and [`crate::gi`]. The group routes octets the caller built.
//!   Rule 7 is its constructor-shaped half: two controlling stations that share
//!   a controlled station get two groups (and two process images); the common
//!   address of the ASDU is the caller's.
//! - **No socket, no thread, no clock.** How the N connections are established
//!   and closed is clause 7.1's business (*"Connection establishment is
//!   performed by the controlling station in case of a controlled station as a
//!   partner"*, index 54, printed 53) and the caller's. [`RedundancyGroup::tick`]
//!   says which members to dial; every time-out is an `Instant` the caller
//!   injects.
//! - **Queues: the connections', a mirror per member, and a gap buffer.** A
//!   member's [`Session`] owns clause 5.3's pending user-data queue, so data
//!   that cannot go out now is held by the connection that will carry it. That
//!   queue is *cleared with the connection* (clause 5.1), which is exactly the
//!   moment 10.5's *"Care shall be taken that data are not lost during a
//!   connection switchover"* applies to, so the group mirrors the ASDUs it
//!   handed to each connection's queue ([`Member::queued_user_data`]) and
//!   captures the mirror with the connection's unconfirmed frames when it
//!   fails. The mirror is filled only by the group's own queueing, drops an
//!   entry as that ASDU goes out, and is trimmed to what the connection's queue
//!   still holds when the member is named again. A caller that queues into a
//!   member's own session is outside it. Between a failure of the started
//!   connection and the next naming, the group itself holds the user data it
//!   is handed ([`RedundancyGroup::held_user_data`]) and queues it on the next
//!   connection named; data still waiting on another stopped connection when
//!   the naming moves joins it. While a failed connection's data waits for the
//!   application's replay decision, the held data waits behind it, so the
//!   replay goes out first (10.6).
//!
//! # What stays the caller's
//!
//! - **How the N connections are established and closed, and how reopening is
//!   retried** (clause 7.1; 10.5's *"reopening is regularly retried by the
//!   controlling station until the error has been corrected and the connection
//!   is re-established"*): the crate holds no socket.
//! - **Which data is retransmitted on switchover** (10.5's *"it is left to the
//!   application if the ESDU is retransmitted"*): [`Replay`], answered with
//!   [`ReplayOutcome`].
//! - **Where the process image lives** (rule 6), and the common address every
//!   routed ASDU carries (rule 7: one group per controlling station).
//! - **Whether a station runs the function at all** (Table 13's NOTE below).
//! - **What to do with each typed refusal**: every [`GroupError`] names the
//!   rule that was broken and the member it was broken on.
//!
//! # Conformance: TS 60870-5-604 Table 13 (PDF indices 58–60, printed 57–59)
//!
//! *"Table 13 – Redundant link conformance test procedures"* names four cases,
//! each marked `M` and each citing *"IEC 60870-5-104:2006, 10"*:
//!
//! - **`5.4.13.1`** *"Periodic check of ALL redundant connections"*: t3 on the
//!   started connection **and on all the stopped connections**, each starting a
//!   TESTFR procedure. This is rule 5, and it is why a member's own
//!   [`Timers`] run while the member is stopped.
//! - **`5.4.13.10`** *"Re-establishing a lost Started connection … (automatic
//!   switch-over)"*: t1 expiry, a new started connection over a still-stopped
//!   one, an active close on the old one, and *"The send- and receive counters
//!   are not reset to "0" as long as the TCP connection is established."*
//! - **`5.4.13.20`** *"Re-establishing a lost redundant connection"*: either
//!   role actively closes an inoperable member and the controlling station
//!   retries a new stopped connection at regular intervals.
//! - **`5.4.13.30`** *"Manual switching over the Started connection to another
//!   redundant Stopped connection: (manual switch-over)"*: STOPDT on the
//!   current started connection, then STARTDT on the selected one.
//!
//! Its NOTE and Remark are the boundary of all four: *"The tests in this Table
//! are only required for systems supporting Redundant connections. If 'M' is
//! mentioned, the test case is mandatory for systems with the relevant Redundant
//! connections options marked in the PICS: – PICS, 9.6, "Redundant connections""*
//! and *"these test cases are describing the redundancy mechanism (with multiple
//! connections to a single Controlled station, of which exactly one is the
//! Started connection and the other connections are Stopped connections), but
//! not how this mechanism will be used in operational redundant systems."*
//! Whether a station runs the function at all is therefore a PICS decision the
//! caller makes: the crate offers the type and refuses nothing for being unused.

use crate::apci::{Apci, ParseError, UFunction};
use crate::asdu::{Coi, LayoutError};
use crate::init::{FollowUp, end_of_initialisation};
use crate::link::{Action, MAX_PENDING_USER_DATA, QueueError, Role, Session, State, Timer};
use crate::params::{LinkParams, ParamError};
use crate::timers::{Supervision, Supervisor, Timers};
use std::time::Instant;

/// One logical connection of a redundancy group: its session and its own
/// time-outs.
///
/// One `Timers` per member, built from that member's [`LinkParams`], is clause
/// 10.7's per-connection t0 to t3 (index 136), and it is also what makes the
/// asymmetric `t1` of the same clause expressible: nothing forces two members
/// to share a `t1`.
///
/// The member also carries the group's bookkeeping about *this* connection: the
/// mirror of the ASDUs the group handed to its clause 5.3 queue
/// ([`Member::queued_user_data`]), what its failed connections left behind for
/// the replay ([`Member::left_behind`]), and whether the application has
/// decided on that data ([`Member::replayed`]).
#[derive(Debug)]
pub struct Member {
    session: Session,
    timers: Timers,
    /// The timer wiring of this member's connection, for the `_at` entry
    /// points and [`RedundancyGroup::tick`].
    supervisor: Supervisor,
    /// The ASDUs the group itself handed to this connection's clause 5.3 queue
    /// (`send_user_data`'s `None` arm) that the connection has not put on the
    /// wire, oldest first. The session owns the queue; this is the group's
    /// mirror of it, kept so that a *lost* connection's queued data is not lost
    /// with the session's queue, which clause 5.1 clears (10.5, index 128:
    /// *"Care shall be taken that data are not lost during a connection
    /// switchover"*).
    queued: Vec<Vec<u8>>,
    /// True once the application has decided on what this member's failed
    /// connection left behind ([`Replay::Retransmit`] or [`Replay::Discard`]),
    /// so that a repeated call is [`GroupError::AlreadyRetransmitted`] rather
    /// than a silent no-op. Cleared by the next failure, and when the member is
    /// named the started connection again.
    replayed: bool,
    /// True between [`RedundancyGroup::on_connection_established`] and
    /// [`RedundancyGroup::on_connection_lost`]: the caller's socket is up,
    /// whatever the session says. A session that closed itself (an active
    /// close) is not connected, but its socket is still the caller's to close,
    /// and nothing may be dialed for the member until it has. The connection
    /// manager keeps the same flag.
    socket: bool,
    /// What this member's failed connections left behind for 10.5/10.6's
    /// replay, oldest first: the I-frames their send buffers never had
    /// confirmed and the ASDUs still in the group's mirror of their clause 5.3
    /// queue. Captured once per failure ([`Member::capture`]), because the
    /// fresh session of a re-established connection starts with nothing
    /// (clause 5.1), and kept, whatever happens to the member afterwards,
    /// until the application decides:
    /// [`Replay::Retransmit`] or [`Replay::Discard`] (10.5: *"it is left to the
    /// application if the ESDU is retransmitted"*). Several unhandled failures
    /// accumulate here.
    left: Vec<Vec<u8>>,
    /// True from the capture of a failure until the member has a live
    /// connection again, so one failure is captured once.
    captured: bool,
    /// When a controlling group's latest attempt for this member began: a
    /// connection lost within its t0 is dialed again when that t0 runs out.
    attempt_began: Option<Instant>,
}

impl Member {
    /// A member of the given role with its own parameters.
    ///
    /// The parameters are validated by both [`Session::with_params`] and
    /// [`Timers::new`]: the session and its scheduler must come from one
    /// parameter set, so the caller configures them together or not at all.
    ///
    /// # Errors
    ///
    /// The [`ParamError`] of [`LinkParams::validate`] for an inadmissible set.
    pub fn new(role: Role, params: LinkParams) -> Result<Self, ParamError> {
        Ok(Self {
            session: Session::with_params(role, params)?,
            timers: Timers::new(params)?,
            supervisor: Supervisor::default(),
            queued: Vec::new(),
            replayed: false,
            socket: false,
            left: Vec::new(),
            captured: false,
            attempt_began: None,
        })
    }

    /// The connection itself: clause 5.1/5.2/5.3's state machine.
    #[must_use]
    pub const fn session(&self) -> &Session {
        &self.session
    }

    /// The connection, for a caller that drives it by hand. Doing so bypasses
    /// the group's naming, its capture of a failure for the replay and its
    /// timer wiring; the group's own methods are the ones that keep those.
    pub const fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    /// This connection's t0–t3 scheduler.
    #[must_use]
    pub const fn timers(&self) -> &Timers {
        &self.timers
    }

    /// The scheduler, for a caller that drives it by hand. Doing so bypasses
    /// the group's timer wiring.
    pub const fn timers_mut(&mut self) -> &mut Timers {
        &mut self.timers
    }

    /// The parameters this member was built from.
    #[must_use]
    pub const fn params(&self) -> &LinkParams {
        self.timers.params()
    }

    /// This connection's state: figures 36/37's boxes, read from the session.
    #[must_use]
    pub const fn state(&self) -> State {
        self.session.state()
    }

    /// The member has a connection: the caller reported its socket up, or
    /// established the session by hand ([`Member::session_mut`]).
    const fn link_up(&self) -> bool {
        self.socket || self.session.is_connected()
    }

    /// An established connection in [`State::Stopped`]: one a switchover or
    /// a Start may use.
    fn is_connected_and_stopped(&self) -> bool {
        self.session.is_connected() && self.session.state() == State::Stopped
    }

    /// The ASDUs the group handed to this connection's clause 5.3 queue that the
    /// connection has not put on the wire yet, oldest first: the group's mirror
    /// of the data a connection switchover must not lose (10.5, index 128,
    /// printed 127).
    ///
    /// The queue itself is the session's ([`Session::pending_user_data`]); this
    /// is only what the group put there (through
    /// [`RedundancyGroup::send_user_data`], or the data it held during a
    /// switchover). When the connection fails, the mirror is captured with the
    /// connection's unconfirmed frames into [`Member::left_behind`]. An entry is
    /// dropped as that ASDU goes out; a re-established connection (clause 5.1)
    /// starts with an empty mirror; and when the member is named the started
    /// connection again the mirror is trimmed to the entries the connection's
    /// own queue still holds, which keeps them on a repeated `STARTDT_ACT`.
    #[must_use]
    pub fn queued_user_data(&self) -> &[Vec<u8>] {
        &self.queued
    }

    /// True once the application has replayed or discarded what this member's
    /// failed connection left behind
    /// ([`RedundancyGroup::retransmit_unconfirmed`]): the record that keeps
    /// the group from putting the same data on the wire twice. The next
    /// failure clears it, and so does naming the member the started
    /// connection again.
    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    /// Records that the group handed one ASDU to this connection's clause 5.3
    /// queue, so the mirror holds what the session holds.
    fn note_queued(&mut self, asdu: &[u8]) {
        self.queued.push(asdu.to_vec());
    }

    /// Drops the mirror entries this connection's own session has just put on
    /// the wire (one per `SendI`), so the mirror never offers for replay data
    /// that has left the connection.
    fn note_wire(&mut self, actions: &[Action]) {
        for action in actions {
            if let Action::SendI { asdu, .. } = action
                && let Some(at) = self.queued.iter().position(|queued| queued == asdu)
            {
                self.queued.remove(at);
            }
        }
    }

    /// Called when the group names this member the started connection. The
    /// record of a replay is dropped: a connection that has failed is only
    /// reachable as [`State::Stopped`] again after the caller re-established it
    /// (clause 5.1, [`Session::on_connection_established`]), so naming it means
    /// a fresh connection. A live connection also drops a stale capture flag.
    /// What a failed connection left behind is not touched: it waits for the
    /// application's decision.
    ///
    /// The mirror is **trimmed, not cleared**: naming a member is not always a
    /// re-establishment. Clause 5.3 (index 38) answers a repeated `STARTDT_ACT`
    /// on the already started connection with a `STARTDT_CON` and leaves its
    /// queue intact, so the group's copy of the data that connection still
    /// holds must stay (10.5's *"Care shall be taken that data are not lost
    /// during a connection switchover"*). Only the newest
    /// [`Session::pending_user_data`] entries of the mirror are kept, because
    /// those are the ones the connection's own queue still accounts for.
    fn reestablish(&mut self) {
        self.replayed = false;
        if self.session.is_connected() {
            self.captured = false;
        }
        let held = self.session.pending_user_data();
        let surplus = self.queued.len().saturating_sub(held);
        self.queued.drain(..surplus);
    }

    /// Records the application's decision (`Retransmit` or `Discard`) on what
    /// this member's failed connections left behind: that data is dropped from
    /// [`Member::left_behind`], and the record keeps a second call from
    /// re-sending it. The frames of a live connection's own send buffer are the
    /// session's and stay there (TS 60870-5-604 `5.4.13.10` keeps the counters).
    fn mark_replayed(&mut self) {
        self.replayed = true;
        self.left.clear();
        // A captured connection's mirror is in `left` already, so it goes; a
        // live connection's mirror is its current queue and stays.
        if self.captured && !self.session.is_connected() {
            self.queued.clear();
        }
    }

    /// Takes what a failed connection leaves behind into [`Member::left_behind`],
    /// once per failure: the frames of its send buffer, then the ASDUs of the
    /// group's queue mirror. A new failure is a new decision for the
    /// application, so the record of an earlier replay goes.
    fn capture(&mut self) {
        if self.captured {
            if !self.session.is_connected() {
                return; // this failure is captured already
            }
            // Re-established by hand since the last capture: a new connection,
            // whose failure this is.
            self.captured = false;
        }
        self.captured = true;
        self.replayed = false;
        let frames = self.session.outstanding_frames().iter();
        self.left.extend(frames.map(|frame| frame.asdu.clone()));
        self.left.extend(self.queued.iter().cloned());
    }

    /// What this member's failed connections left behind and the application
    /// has neither replayed nor discarded yet, oldest first
    /// ([`RedundancyGroup::retransmit_unconfirmed`]).
    #[must_use]
    pub fn left_behind(&self) -> &[Vec<u8>] {
        &self.left
    }
}

/// The [`Action::ActiveClose`] reason of a connection clause 10.7 closes
/// because a Start went out on another one.
pub const CLOSED_BY_START: &str = "closed by a Start on another connection (10.7)";

/// The [`Action::ActiveClose`] reason of [`RedundancyGroup::close`].
pub const CLOSED_BY_APPLICATION: &str = "closed by the application (connection change)";

/// A redundancy group: N logical connections that act as one (rule 2).
///
/// The group owns its members and the name of the started connection. It holds
/// no process image, no socket and no clock (see the module doc); the only user
/// data it holds itself is what it is handed while no connection is started
/// after a failure ([`RedundancyGroup::held_user_data`]).
#[derive(Debug)]
pub struct RedundancyGroup {
    role: Role,
    members: Vec<Member>,
    started: Option<usize>,
    /// User data handed over while no connection was started (between a
    /// failure and the next naming), or moved off a stopped connection the
    /// naming left, held until a connection is named (10.5: *"Care shall be
    /// taken that data are not lost during a connection switchover"*).
    held: Vec<Vec<u8>>,
    /// True from the failure of the started connection until the next one is
    /// named: the gap in which the group holds user data. Before the first
    /// Start there is no such gap, and user data is refused.
    switching: bool,
    /// Every member action list the current call produced, in order, for the
    /// routed `_at` entry points.
    log: Vec<(usize, Vec<Action>)>,
}

impl RedundancyGroup {
    /// A group of one member per parameter set: N logical connections (rule 1).
    ///
    /// One [`LinkParams`] per connection is the general case: a group whose
    /// members carry different `t1` is exactly what clause 10.7's asymmetric
    /// time-outs ask for. [`RedundancyGroup::uniform`] is the shorthand for the
    /// common case where they are equal.
    ///
    /// Refuses [`GroupError::NoMembers`] for an empty list (zero connections
    /// cannot represent one redundancy group, rule 2) and
    /// [`GroupError::Params`] for a parameter set the standard's ranges reject.
    ///
    /// # Errors
    ///
    /// [`GroupError::NoMembers`] for an empty list, and [`GroupError::Params`]
    /// for the first inadmissible parameter set.
    pub fn new(role: Role, params: Vec<LinkParams>) -> Result<Self, GroupError> {
        if params.is_empty() {
            return Err(GroupError::NoMembers);
        }
        let members = params
            .into_iter()
            .map(|one| Member::new(role, one))
            .collect::<Result<Vec<_>, _>>()
            .map_err(GroupError::Params)?;
        Ok(Self {
            role,
            members,
            started: None,
            held: Vec::new(),
            switching: false,
            log: Vec::new(),
        })
    }

    /// A group of `count` members that share one parameter set.
    ///
    /// # Errors
    ///
    /// As [`RedundancyGroup::new`], so [`GroupError::NoMembers`] when `count`
    /// is zero.
    pub fn uniform(role: Role, params: LinkParams, count: usize) -> Result<Self, GroupError> {
        Self::new(role, vec![params; count])
    }

    /// The role of every member of this group.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// N, the number of logical connections the group handles (rule 1).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.members.len()
    }

    /// False for every constructed group: a group without members is refused by
    /// [`RedundancyGroup::new`] rather than built (rule 2).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The members, in index order.
    #[must_use]
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// One member, or [`GroupError::MemberIndexOutOfRange`].
    ///
    /// # Errors
    ///
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member.
    pub fn member(&self, index: usize) -> Result<&Member, GroupError> {
        let members = self.members.len();
        self.members
            .get(index)
            .ok_or(GroupError::MemberIndexOutOfRange { index, members })
    }

    /// One member, mutably, or [`GroupError::MemberIndexOutOfRange`].
    ///
    /// # Errors
    ///
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member.
    pub fn member_mut(&mut self, index: usize) -> Result<&mut Member, GroupError> {
        let members = self.members.len();
        self.members
            .get_mut(index)
            .ok_or(GroupError::MemberIndexOutOfRange { index, members })
    }

    /// One member's connection state, or [`GroupError::MemberIndexOutOfRange`].
    ///
    /// # Errors
    ///
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member.
    pub fn state(&self, index: usize) -> Result<State, GroupError> {
        Ok(self.member(index)?.state())
    }

    /// The started connection's index, or `None` while the group names none.
    #[must_use]
    pub const fn started_index(&self) -> Option<usize> {
        self.started
    }

    /// The started connection (rule 3): the one connection of the group that
    /// carries user data, or [`GroupError::NoStartedConnection`].
    ///
    /// The group's naming is 10.2's *"started connection"* (see the module
    /// doc). [`RedundancyGroup::select`] and [`RedundancyGroup::start`] are the
    /// controlling station's decision of rule 4, and
    /// [`RedundancyGroup::observe_startdt_act`] the controlled station's
    /// positional one. A group names at most one connection because the field
    /// holds one index.
    ///
    /// # Errors
    ///
    /// [`GroupError::NoStartedConnection`] while the group names none.
    pub fn started(&self) -> Result<usize, GroupError> {
        self.started.ok_or(GroupError::NoStartedConnection)
    }

    /// Checks one member against rule 3: it may carry user data only if it is
    /// the started connection.
    ///
    /// The order of the refusals is the order of the checks: a name that is no
    /// member of this group is [`GroupError::MemberIndexOutOfRange`], a group
    /// that names no started connection is [`GroupError::NoStartedConnection`],
    /// and a member that is not that connection is
    /// [`GroupError::NotStartedConnection`].
    ///
    /// # Errors
    ///
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member,
    /// [`GroupError::NoStartedConnection`] while the group names none, and
    /// [`GroupError::NotStartedConnection`] when `index` is another member.
    pub fn route(&self, index: usize) -> Result<usize, GroupError> {
        self.member(index)?;
        let started = self.started()?;
        if started != index {
            return Err(GroupError::NotStartedConnection { index });
        }
        Ok(started)
    }

    /// Hands one user ASDU to the named connection, which rule 3 requires to be
    /// the started one.
    ///
    /// `Some(action)` is the I-frame to put on the wire, from
    /// [`Session::send_i_frame`]. `None` means the ASDU is held, in one of two
    /// places:
    ///
    /// - in the started connection's own clause 5.3 queue
    ///   ([`Session::pending_user_data`]), when that connection may not carry
    ///   user data yet or its k window is full (clause 5.5). A controlling
    ///   station may send once its STARTDT act is out
    ///   ([`Session::user_data_allowed`]); a controlled station only once it is
    ///   `Started`. The group keeps a mirror of the queued ASDU
    ///   ([`Member::queued_user_data`]), because that queue is cleared with the
    ///   connection (clause 5.1) and 10.5 requires *"that data are not lost
    ///   during a connection switchover"*;
    /// - in the group ([`RedundancyGroup::held_user_data`]), when the started
    ///   connection failed and no other has been named yet, or the group
    ///   already holds data. The data goes into the queue of the next
    ///   connection named, once no failed connection's data waits for the
    ///   replay decision.
    ///
    /// A terminated connection that is still named refuses with
    /// [`GroupError::Queue`], and so does the group once it holds
    /// [`MAX_PENDING_USER_DATA`] ASDUs not yet confirmed or decided on (its held
    /// data, every member's queue mirror, unconfirmed frames and
    /// [`Member::left_behind`], a failed connection's data counted once): a
    /// STARTDT act or a replay decision may never come, so the data is refused
    /// rather than piled up or dropped.
    ///
    /// For a controlled station this is 10.4's monitor direction (index 124,
    /// printed 123): *"no user data is transmitted from the controlled station
    /// until started state on one connection is established"*. Before the
    /// peer's first `STARTDT_ACT` the group names no started connection and this
    /// refuses with [`GroupError::NoStartedConnection`]; once the act has named
    /// one, clause 5.3's queue holds the data until the `STARTDT con`
    /// ([`RedundancyGroup::on_startdt_act`] returns that con together with the
    /// released data).
    ///
    /// The octets are the caller's, byte for byte: the group holds no process
    /// image of its own (rule 6).
    ///
    /// # Errors
    ///
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member,
    /// [`GroupError::NoStartedConnection`] or
    /// [`GroupError::NotStartedConnection`] when it may not carry user data
    /// (rule 3), and [`GroupError::Queue`] when the connection refuses to queue
    /// the ASDU or the group is full ([`QueueError::Full`]).
    pub fn send_user_data(
        &mut self,
        index: usize,
        asdu: &[u8],
    ) -> Result<Option<Action>, GroupError> {
        self.member(index)?;
        let in_hand = self.members.iter().fold(self.held.len(), |sum, member| {
            let sum = sum.saturating_add(member.left.len());
            if member.captured && !member.session.is_connected() {
                // A failed connection's data is in `left` now; its queue mirror
                // and unconfirmed frames are stale copies of it.
                return sum;
            }
            sum.saturating_add(member.queued.len())
                .saturating_add(member.session.outstanding_frames().len())
        });
        if in_hand >= MAX_PENDING_USER_DATA {
            return Err(GroupError::Queue(QueueError::Full));
        }
        self.deliver(index, asdu)
    }

    /// [`RedundancyGroup::send_user_data`] without the group's limit, for the
    /// replay of data the limit already counted.
    fn deliver(&mut self, index: usize, asdu: &[u8]) -> Result<Option<Action>, GroupError> {
        if (self.started.is_none() && self.switching) || !self.held.is_empty() {
            // Between a failure and the next Start there is no connection to
            // carry it; the group holds it for the next one named. Data the
            // group already holds (waiting for the replay decision) goes
            // first, so new data queues behind it.
            self.held.push(asdu.to_vec());
            return Ok(None);
        }
        let index = self.route(index)?;
        let member = self.member_mut(index)?;
        // Clause 5.3's queue is older than this ASDU: while it holds anything
        // the ASDU queues behind it, so nothing overtakes it (10.6's order).
        let sent = if member.session.pending_user_data() > 0 {
            None
        } else {
            member.session.send_i_frame(asdu)
        };
        if let Some(action) = sent {
            self.log.push((index, vec![action.clone()]));
            Ok(Some(action))
        } else {
            // Clause 5.3's pending queue, owned by the connection that will
            // carry the data, not by a second member; the group only mirrors it.
            member
                .session
                .queue_i_frame(asdu)
                .map_err(GroupError::Queue)?;
            member.note_queued(asdu);
            Ok(None)
        }
    }

    /// Rule 4: the controlling station decides which connection is the started
    /// one.
    ///
    /// This is the decision, not the procedure that carries it out: the STARTDT
    /// act of clause 5.3 goes out with [`RedundancyGroup::start`] (10.3). User
    /// data still waiting on another established, stopped connection moves into
    /// the group's held data, which the next [`RedundancyGroup::start`] queues
    /// on the named connection. A controlled station has no such decision to
    /// make and is refused with [`GroupError::CannotSelect`] (rule 4 and 10.2's
    /// *"the selection and switchover of the started connection is always
    /// initiated by the controlling station"*). Naming the connection that is
    /// already the group's is [`GroupError::AlreadyInState`].
    ///
    /// # Errors
    ///
    /// [`GroupError::CannotSelect`] for a controlled group,
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member, and
    /// [`GroupError::AlreadyInState`] when it is already the started one.
    pub fn select(&mut self, index: usize) -> Result<(), GroupError> {
        if self.role != Role::Controlling {
            return Err(GroupError::CannotSelect);
        }
        let state = self.member(index)?.state();
        if self.started == Some(index) {
            return Err(GroupError::AlreadyInState { index, state });
        }
        self.sweep_stopped(index);
        self.started = Some(index);
        Ok(())
    }

    /// Rule 4's controlled-station half: the connection on which this station
    /// last received a `STARTDT_ACT` is the started connection.
    ///
    /// Verbatim (index 118): *"The controlled station (station B) always
    /// understands the connection on which it last received a `STARTDT_ACT` as the
    /// started connection."* A repeated act on the same connection names the
    /// same connection again and is not a refusal: clause 5.3 answers every
    /// STARTDT act with a STARTDT con, retransmissions included.
    ///
    /// A controlling station does not learn its started connection this way
    /// (its own choice is [`RedundancyGroup::select`]), so it is refused with
    /// [`GroupError::CannotSelect`].
    ///
    /// This sends nothing: it names the connection and moves the group's held
    /// data (and data waiting on other stopped connections) into that
    /// connection's clause 5.3 queue. [`RedundancyGroup::on_startdt_act`] is
    /// the same naming with the received
    /// frame wired into the member's session (10.4, index 124).
    ///
    /// # Errors
    ///
    /// [`GroupError::CannotSelect`] for a controlling group, and
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member.
    pub fn observe_startdt_act(&mut self, index: usize) -> Result<(), GroupError> {
        if self.role != Role::Controlled {
            return Err(GroupError::CannotSelect);
        }
        self.member(index)?;
        self.name(index);
        Ok(())
    }

    /// Names one member the group's started connection.
    ///
    /// Data still waiting on other stopped connections is swept into the
    /// group's held data first (`sweep_stopped`). Naming a connection is the
    /// group's way of saying that this member is a live one again: a failed
    /// connection only returns to [`State::Stopped`] through the caller's
    /// re-establishment (clause 5.1), so the record of a replay is dropped and
    /// the mirror is trimmed to what the connection's own queue still holds
    /// (`Member::reestablish`). A member that is named again while it is alive
    /// (a repeated `STARTDT_ACT` of clause 5.3) keeps the mirror entries its
    /// session still holds. The held data then goes into the named
    /// connection's queue.
    fn name(&mut self, index: usize) {
        self.sweep_stopped(index);
        self.started = Some(index);
        self.switching = false;
        if let Some(member) = self.members.get_mut(index) {
            member.reestablish();
        }
        self.release_held();
    }

    /// Moves the group's held data into the started connection's clause 5.3
    /// queue, which sends it once data transfer is on. A connection that
    /// cannot take it leaves it held.
    ///
    /// Not while any member still has data left behind that the application
    /// has not decided on: that data is older than what the group holds, and
    /// 10.6's *"any unconfirmed user data will be retransmitted on the new
    /// started connection"* puts it on the wire first. The decision
    /// ([`RedundancyGroup::retransmit_unconfirmed`]) releases the held data
    /// behind it.
    fn release_held(&mut self) {
        if self.members.iter().any(|member| !member.left.is_empty()) {
            return;
        }
        let Some(member) = self.started.and_then(|index| self.members.get_mut(index)) else {
            return;
        };
        let mut kept = Vec::new();
        for asdu in std::mem::take(&mut self.held) {
            if member.session.queue_i_frame(&asdu).is_ok() {
                member.note_queued(&asdu);
            } else {
                kept.push(asdu);
            }
        }
        self.held = kept;
    }

    /// Moves the queued data of every other established, stopped connection
    /// into the front of the group's held data.
    ///
    /// User data is only ever queued on the connection the group names, so a
    /// stopped connection with data waiting was left behind by a naming that
    /// moved on: 10.2's manual switchover, a naming that moved while the
    /// connection was still stopping, or `select` onto a connection that was
    /// down. That data never went out, and it goes into the next started
    /// connection's queue instead of staying on a connection that no longer
    /// carries user data (10.5: *"Care shall be taken that data are not lost
    /// during a connection switchover"*).
    ///
    /// Only stopped connections: nothing of theirs is unconfirmed, so nothing
    /// older can arrive later. A connection that is not stopped is closed by
    /// 10.7 instead, and its queue is captured behind its unconfirmed frames,
    /// in order ([`Member::left_behind`]).
    fn sweep_stopped(&mut self, next: usize) {
        let mut moved = Vec::new();
        for (m, member) in self.members.iter_mut().enumerate() {
            if m != next
                && member.session.is_connected()
                && member.state() == State::Stopped
                && member.session.pending_user_data() > 0
            {
                moved.extend(member.session.take_pending_user_data());
                member.queued.clear();
            }
        }
        self.held.splice(0..0, moved);
    }

    /// User data held by the group because no connection is started, or
    /// because what a failed connection left behind, which is older, still
    /// waits for [`RedundancyGroup::retransmit_unconfirmed`]'s `Retransmit` or
    /// `Discard`.
    ///
    /// That decision is required for user data to flow again: while a failure
    /// is undecided, every later [`RedundancyGroup::send_user_data`] is held
    /// here too ([`Replay::Leave`] decides nothing).
    #[must_use]
    pub fn held_user_data(&self) -> &[Vec<u8>] {
        &self.held
    }

    /// 10.4's controlled-station procedure, figure 33's (index 126, printed
    /// 125) `receive STARTDT` / `U (STARTDT act)`: one received `STARTDT_ACT`,
    /// wired into the connection it arrived on and named the group's started
    /// connection.
    ///
    /// The frame is fed to the named member's own [`Session::on_frame`], which
    /// answers clause 5.3's `STARTDT_CON` and moves that connection to
    /// [`State::Started`], and the member is named the group's started
    /// connection through [`RedundancyGroup::observe_startdt_act`] (10.2's
    /// *"the connection on which it last received a `STARTDT_ACT`"*). The
    /// session's actions are returned unchanged: the `STARTDT_CON`, followed by
    /// any monitoring data the connection held, because clause 5.3 (index 38,
    /// printed 37) says *"Any pending user data in the controlled station is
    /// sent only after the STARTDT con."*
    ///
    /// Refusals: [`GroupError::CannotSelect`] for a controlling group, which
    /// takes its naming from its own decision ([`RedundancyGroup::select`]);
    /// [`GroupError::MemberIndexOutOfRange`] for a name that is no member of
    /// this group; and [`GroupError::NotConnected`] for an act on a controlled
    /// member whose session is over (closed, its loss not reported yet), which
    /// names nothing and leaves the data the group holds held.
    ///
    /// A repeated act on the connection that already is the group's names it
    /// again and closes nothing (clause 5.3 answers every STARTDT act with a
    /// STARTDT con). An act on another member moves the naming, and 10.7's close
    /// rule (index 136, *"Any connection that is not in the STOPPED state is
    /// immediately closed at the event of a Start on a new connection."*)
    /// closes every other member that is not stopped. Figure 36's label
    /// `STARTDT act[]/Close other not stopped connection(s)/Send STARTDT con`
    /// puts the close first, so the close actions come first, in member order,
    /// then the connection's own answer. What waits in a closed connection's
    /// clause 5.3 queue is captured for the replay ([`Member::left_behind`]);
    /// what waits on a stopped one moves to the new connection's queue (10.5:
    /// *"Care shall be taken that data are not lost during a connection
    /// switchover"*).
    ///
    /// # Errors
    ///
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member,
    /// [`GroupError::NotConnected`] when a controlled group's member has no
    /// connection, and [`GroupError::CannotSelect`] for a controlling group.
    pub fn on_startdt_act(&mut self, index: usize) -> Result<Vec<Action>, GroupError> {
        if self.role == Role::Controlled && !self.member(index)?.session.is_connected() {
            // An act on a connection that is already over (closed, its loss
            // not reported yet) starts nothing and names nothing.
            return Err(GroupError::NotConnected { index });
        }
        let already_named = self.started == Some(index);
        self.observe_startdt_act(index)?;
        let mut actions = if already_named {
            Vec::new()
        } else {
            self.close_others(index)
        };
        let answered = self
            .member_mut(index)?
            .session_mut()
            .on_frame(Apci::U(UFunction::StartDtAct));
        self.member_mut(index)?.note_wire(&answered);
        self.record(index, &answered);
        actions.extend(answered);
        Ok(actions)
    }

    /// Feeds one received frame of one connection.
    ///
    /// The group is the layer that knows which connection is the started one
    /// (rule 3), so it is also the layer that decides which frames a connection
    /// may handle. Two sentences of clause 10 are that decision, and both are
    /// about acknowledging:
    ///
    /// > The controlled station shall only acknowledge user data received on the
    /// > connection on which it last received a STARTDT_ACT (the started
    /// > connection).  (10.5, index 128, printed 127)
    ///
    /// > The controlling station shall not acknowledge user data received on a
    /// > connection which is not started.  (10.6, index 132, printed 131)
    ///
    /// So an I-frame or an S-frame arriving on a connection that is not the
    /// group's started connection is refused with
    /// [`GroupError::NotStartedConnection`] and is **not** fed to that
    /// connection's session: nothing is acknowledged on that connection and its
    /// receive counter stays where it was. The connection's own reaction to data
    /// arriving before STARTDT (clause 5.3's `S-frame[]/Active close` and
    /// `I-frame[]/Active close` out of `STOPPED`, figures 17/18) is the
    /// session's, reached directly through [`Member::session_mut`] when the
    /// caller wants the link's answer instead of the group's refusal.
    ///
    /// U-frames are the connection's own on every member, because the Start/Stop
    /// procedure of clause 5.3 and the TESTFR supervision of rule 5 (clause 5.2;
    /// TS 60870-5-604 `5.4.13.1`, index 58, *"Periodic check of ALL redundant
    /// connections"*) are per connection and run on the stopped connections too.
    /// One of them is the group's business as well: a `STARTDT_ACT` received by a
    /// controlled station is 10.4's naming, so it is handed to
    /// [`RedundancyGroup::on_startdt_act`] and the frame and the naming stay one
    /// call.
    ///
    /// Refusals, in order: a name that is no member of the group is
    /// [`GroupError::MemberIndexOutOfRange`]; an I- or S-frame on a connection
    /// that is not the started one is [`GroupError::NotStartedConnection`]; and
    /// a controlled station's `STARTDT_ACT` has
    /// [`RedundancyGroup::on_startdt_act`]'s refusals.
    ///
    /// # Errors
    ///
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member,
    /// [`GroupError::NotStartedConnection`] for an S- or I-frame on a member
    /// that is not the started connection, and the errors of
    /// [`RedundancyGroup::on_startdt_act`] for a `STARTDT act` received by a
    /// controlled group.
    pub fn on_frame(&mut self, index: usize, apci: Apci) -> Result<Vec<Action>, GroupError> {
        self.member(index)?;
        match apci {
            Apci::U(UFunction::StartDtAct) if self.role == Role::Controlled => {
                self.on_startdt_act(index)
            }
            Apci::U(_) => {
                let actions = self.member_mut(index)?.session_mut().on_frame(apci);
                self.member_mut(index)?.note_wire(&actions);
                self.record(index, &actions);
                Ok(actions)
            }
            Apci::S { .. } | Apci::I { .. } => {
                if self.started != Some(index) {
                    return Err(GroupError::NotStartedConnection { index });
                }
                let actions = self.member_mut(index)?.session_mut().on_frame(apci);
                self.member_mut(index)?.note_wire(&actions);
                self.record(index, &actions);
                Ok(actions)
            }
        }
    }

    /// 10.7's close rule (index 136), verbatim: *"Any connection that is not in
    /// the STOPPED state is immediately closed at the event of a Start on a new
    /// connection."*
    ///
    /// Every member but `keep` whose session is neither [`State::Stopped`] (the
    /// rule's own exception) nor [`State::Terminated`] (closed already) is
    /// actively closed through its own session with [`CLOSED_BY_START`], in
    /// member order. Figure 36's transition (`STARTDT act[]/Close other not
    /// stopped connection(s)/Send STARTDT con`) prints that close before the
    /// confirmation, so the callers put these actions first.
    fn close_others(&mut self, keep: usize) -> Vec<Action> {
        let mut actions = Vec::new();
        for index in 0..self.members.len() {
            if index == keep {
                continue;
            }
            let Ok(state) = self.state(index) else {
                continue;
            };
            if state == State::Stopped || state == State::Terminated {
                continue;
            }
            actions.extend(self.close_member(index, CLOSED_BY_START));
        }
        actions
    }

    /// One connection's active close, through [`Session::close`] with `why` as
    /// its reason: the pending acknowledgement first, when the peer is owed one
    /// (figures 10/11's NOTE), then [`Action::ActiveClose`]. Clause 10 uses it
    /// for figure 37's `User application requests connection change[]/Active
    /// close` (index 140) and figure 36's `Close initiated by another
    /// connection[]/` (index 138). Recording the close captures what the
    /// connection leaves behind for the replay.
    ///
    /// A closed connection is no longer the group's started one: the naming is
    /// dropped when this was it (rule 3, index 118: the group names one started
    /// connection, and a terminated one cannot carry user data).
    fn close_member(&mut self, index: usize, why: &'static str) -> Vec<Action> {
        let Ok(member) = self.member_mut(index) else {
            return Vec::new();
        };
        let actions = member.session_mut().close(why);
        self.record(index, &actions);
        if self.started == Some(index) {
            self.started = None;
        }
        actions
    }

    /// What a member's failed connections left behind and the application has
    /// not decided on yet, oldest first ([`Member::left_behind`]): for each
    /// failure, the I-frames its send buffer had not confirmed followed by the
    /// ASDUs of the group's mirror of its clause 5.3 queue.
    fn held_by(&self, index: usize) -> Result<Vec<Vec<u8>>, GroupError> {
        Ok(self.member(index)?.left.clone())
    }

    /// Reports one timer expiry of one connection and, on the started
    /// connection's `t1`, performs the group's switchover.
    ///
    /// Every expiry is first the connection's own: the member's
    /// [`Session::on_timeout`] answers t1 with the active close of figures 17/18,
    /// t2 with the acknowledgement S-frame of clause 5.1 and t3 with the
    /// `TESTFR act` of clause 5.2 (rule 5; [`Timers`] decides when each is
    /// due), and those actions come back unchanged in
    /// [`TimeoutOutcome::actions`], first on the wire.
    ///
    /// A `t1` on the group's **started** connection is also 10.5's switchover
    /// trigger (index 128, printed 127): *"When transmission timeout (t1) has
    /// elapsed, one of the stopped connections (connection n) is started using
    /// the STARTDT function"*. The same expiry covers *"A connection switchover
    /// will also be performed whenever a `TESTFR_ACT` on the started connection
    /// fails"*, because that failure is the t1 supervising the act
    /// ([`Session::test_pending`]; figure 14's `Time-out t1` → `Active close`).
    /// A controlling group then starts the first other member that is
    /// established and [`State::Stopped`], names it the started connection and
    /// appends that connection's [`Session::request_start`] actions behind the
    /// failed connection's own. 10.7's close rule belongs to this Start as much
    /// as to [`RedundancyGroup::start`], so any *other* member that is not
    /// stopped is closed first (the failed connection is already terminated by
    /// its own t1 reaction). [`TimeoutOutcome::switchover`] says which of the
    /// three cases it was: [`Switchover::Automatic`],
    /// [`Switchover::NoStoppedConnection`] when no stopped connection was left
    /// to start, or [`Switchover::LeftToTheControllingStation`] for a controlled
    /// group, which performs no switchover of its own (rule 4, index 118). In
    /// the last two cases the group names no started connection and holds the
    /// user data it is handed until one is named.
    ///
    /// Rule 4's choice stays the caller's: a caller that wants a particular
    /// connection switches over itself through [`RedundancyGroup::select`] and
    /// [`RedundancyGroup::start`] (10.2's manual switchover), and this method
    /// then sees the failure on a connection that is no longer the group's
    /// started one.
    ///
    /// The trigger is the started connection and no other: a t1 on a stopped
    /// connection closes that connection and moves no naming, and a t1 on a
    /// connection that is already [`State::Terminated`] is no failure at all.
    ///
    /// Reopening the failed connection is the caller's next step: the crate
    /// holds no socket (clause 7.1, index 54). What must not be lost is what the
    /// failed connection still held (10.5's *"Care shall be taken that data are
    /// not lost during a connection switchover, for example by doing a station
    /// interrogation procedure after a switchover has been performed."*). The
    /// close captures it, and [`Switchover`]'s `unconfirmed` counts what the
    /// member now holds for [`RedundancyGroup::retransmit_unconfirmed`]: the
    /// I-frames still in the connection's send buffer **plus** the ASDUs of the
    /// group's mirror of its clause 5.3 queue (which the close itself empties,
    /// clause 5.1), plus whatever earlier failures of the member left undecided.
    /// 10.3's interrogation is [`RedundancyGroup::follow_up`]'s value once the
    /// new connection has completed its start.
    ///
    /// # Errors
    ///
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member.
    pub fn on_timeout(&mut self, index: usize, timer: Timer) -> Result<TimeoutOutcome, GroupError> {
        let state = self.member(index)?.state();
        let mut actions = self.member_mut(index)?.session_mut().on_timeout(timer);
        self.record(index, &actions);
        self.member_mut(index)?.note_wire(&actions);
        let mut switchover = None;

        if timer == Timer::T1 && self.started == Some(index) && state != State::Terminated {
            let unconfirmed = self.held_by(index)?.len();
            if self.role == Role::Controlling {
                let takeover = self.members.iter().enumerate().position(|(other, member)| {
                    other != index && member.is_connected_and_stopped()
                });
                if let Some(new) = takeover {
                    // 10.7's close rule belongs to this Start as well: it
                    // is a Start on a new connection like any other, and
                    // the failed one is only out of it because its own t1
                    // reaction already terminated it.
                    actions.extend(self.close_others(new));
                    self.name(new);
                    let started = self.member_mut(new)?.session_mut().request_start();
                    self.record(new, &started);
                    self.member_mut(new)?.note_wire(&started);
                    actions.extend(started);
                    switchover = Some(Switchover::Automatic {
                        failed: index,
                        started: new,
                        unconfirmed,
                    });
                } else {
                    self.started = None;
                    self.switching = true;
                    switchover = Some(Switchover::NoStoppedConnection {
                        failed: index,
                        unconfirmed,
                    });
                }
            } else {
                // Rule 4: the switchover of the started connection is always
                // initiated by the controlling station, so a controlled station
                // reports the failure and waits for the peer's STARTDT_ACT.
                // The failed connection is terminated: it is no longer the
                // started one, and data waits in the group until the peer names
                // another.
                self.started = None;
                self.switching = true;
                switchover = Some(Switchover::LeftToTheControllingStation {
                    failed: index,
                    unconfirmed,
                });
            }
        }

        Ok(TimeoutOutcome {
            actions,
            switchover,
        })
    }

    /// 10.5's retransmission decision: *"it is left to the application if the
    /// ESDU is retransmitted"* (index 128, printed 127).
    ///
    /// 10.5 directs the command to the new started connection *"either by
    /// re-transmitting the ASDU on this connection or by terminating the ongoing
    /// application function and reinitiating it towards the new connection"*,
    /// and 10.6 (index 132, printed 131) adds: *"In general, any unconfirmed user
    /// data will be retransmitted on the new started connection after a
    /// connection switchover has been performed, including potential unconfirmed
    /// ACTCONs or ACTTERMs."*
    ///
    /// `failed` names the member whose connection failed. What that connection
    /// left behind was captured once, when it failed (the frames its send
    /// buffer held, then the group's mirror of its clause 5.3 queue, oldest
    /// first), and is kept in [`Member::left_behind`] across the reopening of
    /// the member and its being started again, because the fresh session
    /// starts with nothing (clause 5.1). Several failures the application has
    /// not decided on add up. A member whose session was closed by hand, past
    /// the group, is captured here first.
    ///
    /// [`Replay::Leave`] only counts it. [`Replay::Discard`] drops it: the
    /// caller's own *"terminating the ongoing application function and
    /// reinitiating it towards the new connection"*. [`Replay::Retransmit`]
    /// hands every held ASDU to the group's started connection, oldest first,
    /// through [`RedundancyGroup::send_user_data`]. That is rule 3's routing:
    /// the data leaves on the one started connection (which may be `failed`
    /// itself on a new connection), and an ASDU that connection cannot put on
    /// the wire yet waits in *its* clause 5.3 queue (counted in
    /// [`ReplayOutcome::Retransmitted`]'s `queued`).
    ///
    /// The user data the group held meanwhile ([`RedundancyGroup::held_user_data`])
    /// is newer, so it waits for this decision: once no member has anything
    /// left behind, `Retransmit` sends it behind the replay (in the same
    /// actions) and `Discard` sends it on the started connection (in
    /// [`ReplayOutcome::Discarded`]'s actions); what that connection cannot put
    /// on the wire yet waits in its clause 5.3 queue, and later user data
    /// queues behind it. `Leave` decides nothing and keeps it held.
    ///
    /// **The decision is required.** After a failure that left data behind,
    /// the group holds *all* later user data until this call returns
    /// `Retransmitted` or `Discarded`; a caller that never decides, or only
    /// ever answers `Leave`, sends no user data again.
    ///
    /// **Once.** `Retransmit` and `Discard` empty what was held and record the
    /// decision ([`Member::replayed`]); a further call with nothing new held is
    /// [`GroupError::AlreadyRetransmitted`], so a caller that retries cannot
    /// duplicate data. The next failure of the member is a new decision.
    ///
    /// The replay is the ASDU and not the frame: the failed connection's `N(S)`
    /// belongs to the failed connection, and *"The send- and receive counters are
    /// not reset to \"0\" as long as the TCP connection is established. Each TCP
    /// connection, not affected by STARTDT and STOPDT procedures or switch-over
    /// procedures, maintains its send- and receive counter."* (TS 60870-5-604
    /// `5.4.13.10`, index 58, printed 57). The new connection stamps its own,
    /// through [`Session::send_i_frame`]. [`Session::retransmit`] is the
    /// same-connection replay, for a caller that wants that connection's own
    /// buffer back as it was stamped.
    ///
    /// Refusals, in order: a name that is no member of the group is
    /// [`GroupError::MemberIndexOutOfRange`]; a member whose data has already been
    /// decided on, with nothing new held, is [`GroupError::AlreadyRetransmitted`];
    /// [`Replay::Retransmit`] for the group's started connection with nothing
    /// held is [`GroupError::StillStartedConnection`] (its own frames are on
    /// the wire, and the group does not duplicate them); and
    /// [`Replay::Retransmit`] while the group names no started connection is
    /// [`GroupError::NoStartedConnection`].
    ///
    /// # Errors
    ///
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member,
    /// [`GroupError::AlreadyRetransmitted`] when its data was already replayed
    /// or discarded, and for [`Replay::Retransmit`]
    /// [`GroupError::StillStartedConnection`],
    /// [`GroupError::NoStartedConnection`] or the errors of
    /// [`RedundancyGroup::send_user_data`].
    pub fn retransmit_unconfirmed(
        &mut self,
        failed: usize,
        replay: Replay,
    ) -> Result<ReplayOutcome, GroupError> {
        let member = self.member_mut(failed)?;
        if member.state() == State::Terminated {
            // A session closed by the caller's own hand (`Member::session_mut`)
            // was never captured: what it left is taken now, before the
            // decision. A close the group saw is captured already, and this
            // is a no-op.
            member.capture();
        }
        let held = member.left.clone();
        if member.replayed() && held.is_empty() {
            return Err(GroupError::AlreadyRetransmitted { index: failed });
        }

        match replay {
            Replay::Leave => Ok(ReplayOutcome::Left {
                unconfirmed: held.len(),
            }),
            Replay::Discard => {
                self.member_mut(failed)?.mark_replayed();
                self.release_held();
                // The started connection may already carry user data (clause
                // 5.3); the released data goes out now, as after `Retransmit`,
                // not at that connection's next acknowledgement.
                let mut actions = Vec::new();
                if let Some(index) = self.started {
                    let member = self.member_mut(index)?;
                    actions = member.session.flush_pending();
                    member.note_wire(&actions);
                    self.record(index, &actions);
                }
                Ok(ReplayOutcome::Discarded {
                    discarded: held.len(),
                    actions,
                })
            }
            Replay::Retransmit => {
                // The started connection has nothing left behind while it runs;
                // only a member that failed and was started again has.
                if self.started == Some(failed) && held.is_empty() {
                    return Err(GroupError::StillStartedConnection { index: failed });
                }
                let index = self.started()?;
                let mut actions = Vec::new();
                let mut queued = 0_usize;
                // What the group holds is newer than the replay: set aside so
                // the replay does not queue behind it, and released after it
                // (10.6).
                let newer = std::mem::take(&mut self.held);
                for asdu in &held {
                    match self.deliver(index, asdu) {
                        Ok(Some(action)) => actions.push(action),
                        Ok(None) => queued = queued.saturating_add(1),
                        Err(error) => {
                            self.held = newer;
                            return Err(error);
                        }
                    }
                }
                self.held = newer;
                self.member_mut(failed)?.mark_replayed();
                self.release_held();
                let member = self.member_mut(index)?;
                let flushed = member.session.flush_pending();
                member.note_wire(&flushed);
                self.record(index, &flushed);
                actions.extend(flushed);
                Ok(ReplayOutcome::Retransmitted { actions, queued })
            }
        }
    }

    /// 10.3's start procedure: figure 32's (index 122, printed 121) and figure
    /// 37's (index 140) `Start connection[]/Send STARTDT act`.
    ///
    /// This is 10.3's *"one of the connections (e.g. connection 1) is therefore
    /// changed from the stopped into the started state"* for one connection:
    /// the STARTDT act of clause 5.3 goes out through the member's own
    /// [`Session::request_start`], whose actions are returned to the caller, and
    /// the group names that connection as its started one (rule 3's one started
    /// connection and rule 4's decision, carried out). User data the group
    /// holds, or that still waits on another stopped connection, goes into the
    /// new connection's queue and out behind the act.
    ///
    /// Establishment stays the caller's (clause 7.1, index 54), and figure 32's
    /// NOTE leaves the order of the connections open, so whichever connection
    /// the caller has brought up may be the one that starts. The `STARTDT con`
    /// stays the caller's too: the caller feeds the received frame to the
    /// member, and [`RedundancyGroup::follow_up`] then says whether 10.3's
    /// station interrogation is due.
    ///
    /// Refusals, in order: a controlled station starts no connection of its own
    /// (rule 4, index 118), so it is [`GroupError::CannotSelect`]; a name that
    /// is no member of the group is [`GroupError::MemberIndexOutOfRange`]; a
    /// connection whose session is not `Stopped` (starting, started, stopping or
    /// terminated) is [`GroupError::AlreadyInState`] with the member's own
    /// state; and a `Stopped` session without a TCP connection is
    /// [`GroupError::NotConnected`].
    ///
    /// The member [`RedundancyGroup::select`] has just named is not refused
    /// while its session is still `Stopped`: naming the connection and starting
    /// it are rule 4's decision and its procedure, so `start` carries the
    /// selection out.
    ///
    /// A connection that has failed is only `Stopped` again after the caller
    /// re-established it (clause 5.1), so starting it is the group's observable
    /// form of a fresh connection: the record of a replay is dropped and the
    /// queue mirror trimmed with the naming.
    ///
    /// # 10.7's close rule
    ///
    /// Verbatim (index 136, printed 135): *"Any connection that is not in the
    /// STOPPED state is immediately closed at the event of a Start on a new
    /// connection."* The event of a Start is this call, so before the new
    /// connection's own act goes out the group actively closes **every other
    /// member that is not [`State::Stopped`]** (a member already
    /// [`State::Terminated`] is left alone) and returns those close actions
    /// first, in member order, as figure 36's `STARTDT act[]/Close other not
    /// stopped connection(s)/Send STARTDT con` prints the close before the
    /// confirmation. Each close is that connection's own [`Session::close`], so
    /// figures 10/11's NOTE (the S-frame before the active close) comes from the
    /// link layer. Without the rule the group would end up with two live
    /// connections, which rule 3 (index 118) forbids: *"Only one logical
    /// connection is in the started state and sending/receiving user data at a
    /// time for one redundancy group."*
    ///
    /// # Errors
    ///
    /// [`GroupError::CannotSelect`] for a controlled group,
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member,
    /// [`GroupError::AlreadyInState`] when the member is not stopped, and
    /// [`GroupError::NotConnected`] when it has no connection.
    pub fn start(&mut self, index: usize) -> Result<Vec<Action>, GroupError> {
        if self.role != Role::Controlling {
            return Err(GroupError::CannotSelect);
        }
        let member = self.member(index)?;
        let state = member.state();
        if state != State::Stopped {
            return Err(GroupError::AlreadyInState { index, state });
        }
        if !member.session().is_connected() {
            return Err(GroupError::NotConnected { index });
        }
        // 10.7: "Any connection that is not in the STOPPED state is immediately
        // closed at the event of a Start on a new connection." (index 136)
        let mut actions = self.close_others(index);
        self.name(index);
        let started = self.member_mut(index)?.session_mut().request_start();
        self.record(index, &started);
        self.member_mut(index)?.note_wire(&started);
        actions.extend(started);
        Ok(actions)
    }

    /// The manual switchover's first request: figure 37's (index 140)
    /// `Stop connection[no unconfirmed I-frames]/Send STOPDT act` and `Stop
    /// connection[unconfirmed I-frames]/Send STOPDT act`.
    ///
    /// 10.2 (index 118, printed 117), verbatim: *"Manual connection switchover
    /// can be performed by first issuing a `STOPDT_ACT` on the currently started
    /// connection and then a `STARTDT_ACT` on the selected new started connection.
    /// This will gracefully terminate data transfer on the first connection
    /// before it is resumed on the new connection."* This method is the first of
    /// those two requests and [`RedundancyGroup::start`] the second, so the
    /// `STOPDT_ACT` is never hidden inside one call. TS 60870-5-604 `5.4.13.30`
    /// (indices 59–60, printed 58–59) is the case step by step; the steps
    /// between the two requests (the `STOPDT_CON`, the S-frames that acknowledge
    /// unacknowledged I-frames) are the caller feeding the peer's frames to the
    /// member until that connection is [`State::Stopped`] again.
    ///
    /// The act itself is the connection's: [`Session::request_stop`] chooses
    /// between the two transitions by the connection's unconfirmed I-frames
    /// (clause 5.3, index 38) and returns the S-frame it owes its peer before the
    /// act when I-frames were received and not yet confirmed. The group returns
    /// those actions unchanged and keeps naming this connection until the caller
    /// moves the naming ([`RedundancyGroup::select`], [`RedundancyGroup::start`])
    /// or the group performs a switchover.
    ///
    /// Refusals, in order: a controlled station stops no connection of its own
    /// (the manual switchover is the controlling station's, rule 4, index 118),
    /// so it is [`GroupError::CannotSelect`]; a name that is no member of the
    /// group is [`GroupError::MemberIndexOutOfRange`]; a name that is not the
    /// group's started connection is [`GroupError::NotStartedConnection`],
    /// because the `STOPDT_ACT` is issued *"on the currently started
    /// connection"*; and a started connection whose session is not
    /// [`State::Started`] (a stop already in flight) is
    /// [`GroupError::AlreadyInState`] with the member's own state.
    ///
    /// # Errors
    ///
    /// [`GroupError::CannotSelect`] for a controlled group,
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member,
    /// [`GroupError::NotStartedConnection`] when it is not the started
    /// connection, and [`GroupError::AlreadyInState`] when it is not started.
    pub fn stop(&mut self, index: usize) -> Result<Vec<Action>, GroupError> {
        if self.role != Role::Controlling {
            return Err(GroupError::CannotSelect);
        }
        self.member(index)?;
        if self.started != Some(index) {
            return Err(GroupError::NotStartedConnection { index });
        }
        let state = self.member(index)?.state();
        if state != State::Started {
            return Err(GroupError::AlreadyInState { index, state });
        }
        let actions = self.member_mut(index)?.session_mut().request_stop();
        self.record(index, &actions);
        self.member_mut(index)?.note_wire(&actions);
        Ok(actions)
    }

    /// Figure 37's (index 140) `User application requests connection change[]/
    /// Active close` (the one transition only clause 10 draws) and figure 36's
    /// (index 138) incoming `Close initiated by another connection[]/`.
    ///
    /// Verbatim (index 136, printed 135): *"Manual switchover is initiated by
    /// the user application either by a Stop on the started connection followed
    /// by a Start on another connection, or simply by issuing a connection change
    /// request."* A connection change request is the second of those two forms:
    /// the caller asks for the connection to be closed, and the group performs
    /// the connection's own active close ([`Session::close`]; the pending
    /// acknowledgement goes first). The returned [`Action::ActiveClose`] carries
    /// [`CLOSED_BY_APPLICATION`], and what the connection leaves behind is
    /// captured for the replay ([`Member::left_behind`]).
    ///
    /// Either role may close a connection: TS 60870-5-604 `5.4.13.20` (index 59,
    /// printed 58) says of the *"Controlling station"* and of the *"Controlled
    /// station"* that it *"initiates a TCP active close on the inoperable
    /// connection (which may never arrive)"*, started or stopped, so there is no
    /// role guard here.
    ///
    /// Closing the group's started connection drops the naming: a terminated
    /// connection is not the started connection, and 10.2's rule 3 gives the
    /// group one at most. Closing the TCP connection and reopening it (10.5's
    /// regular retry, index 128) are the caller's next steps.
    ///
    /// The refusal is a connection that is already [`State::Terminated`] (there
    /// is nothing left to close), as [`GroupError::AlreadyInState`] with that
    /// state; a name that is no member of the group is
    /// [`GroupError::MemberIndexOutOfRange`].
    ///
    /// # Errors
    ///
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member, and
    /// [`GroupError::AlreadyInState`] when it is already terminated.
    pub fn close(&mut self, index: usize) -> Result<Vec<Action>, GroupError> {
        let state = self.member(index)?.state();
        if state == State::Terminated {
            return Err(GroupError::AlreadyInState { index, state });
        }
        Ok(self.close_member(index, CLOSED_BY_APPLICATION))
    }

    /// 10.3's `ENDINIT.req`, as the caller's typed parameter.
    ///
    /// Verbatim (index 120, printed 119): *"The ENDINIT.req (optional but
    /// recommended, Figures 32 and 33) may always be useful to advise the other
    /// station that the sending station is now ready to respond to an
    /// interrogation request. In case of initialisation of the controlling
    /// station, it is only issued if data in the reverse direction is
    /// defined."* Figure 32 (index 122) prints the primitive as `A_ENDINIT.req`
    /// and `A_ENDINIT.ind` with `<SEND=M_EI>`, marked `(optional)`.
    ///
    /// Neither the decision nor the frame is the group's invention: the
    /// optionality and 10.3's reverse-direction condition are the caller's
    /// ([`EndInit`]), and the octets are [`end_of_initialisation`]'s, the
    /// crate's one `M_EI_NA_1`. The frame travels the way any other user ASDU of
    /// the group travels ([`RedundancyGroup::send_user_data`], rule 3): out on
    /// the started connection when its session may carry data, into that
    /// connection's own clause 5.3 queue when it may not.
    ///
    /// `Ok(None)` when [`EndInit::reverse_direction_data`] is false: nothing is
    /// issued, on any connection, and the group does not look for a started one.
    /// When it is true and the group names no started connection, the refusal is
    /// [`GroupError::NoStartedConnection`].
    ///
    /// 10.3 is the controlling station's initialisation, so a controlled group
    /// is refused with [`GroupError::CannotSelect`] before 10.3's condition is
    /// even looked at, as [`RedundancyGroup::start`] refuses the same role. A
    /// controlled station that must announce its own restart builds the frame
    /// itself and hands it over through [`RedundancyGroup::send_user_data`] (see
    /// the module doc's 10.4 section).
    ///
    /// # Errors
    ///
    /// [`GroupError::CannotSelect`] for a controlled group,
    /// [`GroupError::NoStartedConnection`] while the group names none,
    /// [`GroupError::Layout`] if the ASDU cannot be built, and the errors of
    /// [`RedundancyGroup::send_user_data`].
    pub fn endinit(&mut self, endinit: EndInit) -> Result<Option<Action>, GroupError> {
        if self.role != Role::Controlling {
            return Err(GroupError::CannotSelect);
        }
        if !endinit.reverse_direction_data {
            return Ok(None);
        }
        let index = self.started()?;
        let asdu = end_of_initialisation(endinit.coi, endinit.common_address, endinit.originator)?;
        self.send_user_data(index, &asdu)
    }

    /// 10.3's station interrogation, as the [`FollowUp`] value of
    /// [`crate::init`].
    ///
    /// Verbatim (index 120, printed 119): *"The controlling station shall
    /// initiate a station interrogation procedure as soon as possible after the
    /// completion of making one of the connections in started state as shown in
    /// Figures 32 and 33."* Figure 32 (index 122) prints it as the box
    /// *"Following function: Station interrogation"*.
    ///
    /// `Some(FollowUp::StationInterrogation)` when `index` is the group's started
    /// connection and that connection has completed its start ([`State::Started`],
    /// i.e. the `STARTDT con` of clause 5.3 has arrived). *"One of the
    /// connections"* is the group's started one, so every other member of the
    /// group is `Ok(None)`, and so is the started connection while it is still
    /// `PendingStarted`: the interrogation follows the *completion* of the start.
    /// The caller performs the request the value names
    /// ([`crate::gi::request`]); the group keeps no latch, so *"as soon as
    /// possible after the completion"* stays the caller's timing and the value
    /// counts nothing.
    ///
    /// A controlled station runs no station interrogation of its own (its
    /// initialisation is 10.4, [`RedundancyGroup::on_startdt_act`]), so it is
    /// [`GroupError::CannotSelect`], like its [`RedundancyGroup::start`]. A name
    /// that is no member of the group is
    /// [`GroupError::MemberIndexOutOfRange`].
    ///
    /// # Errors
    ///
    /// [`GroupError::CannotSelect`] for a controlled group, and
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member.
    pub fn follow_up(&self, index: usize) -> Result<Option<FollowUp>, GroupError> {
        if self.role != Role::Controlling {
            return Err(GroupError::CannotSelect);
        }
        let state = self.member(index)?.state();
        if self.started == Some(index) && state == State::Started {
            Ok(Some(FollowUp::StationInterrogation))
        } else {
            Ok(None)
        }
    }
}

/// 10.3's `ENDINIT.req` as the caller's typed parameter (figure 32, index 122,
/// printed 121, prints `A_ENDINIT.req`, `A_ENDINIT.ind` and `<SEND=M_EI>`).
///
/// Verbatim (index 120, printed 119): *"The ENDINIT.req (optional but
/// recommended, Figures 32 and 33) may always be useful to advise the other
/// station that the sending station is now ready to respond to an interrogation
/// request. In case of initialisation of the controlling station, it is only
/// issued if data in the reverse direction is defined."*
///
/// The optionality is the caller's: [`RedundancyGroup::endinit`] is called when
/// the station wants it, and the group issues nothing when
/// [`reverse_direction_data`](EndInit::reverse_direction_data) is false. It is
/// the *controlling* station's parameter: a controlled group refuses the call
/// with [`GroupError::CannotSelect`] (10.3, index 120, printed 119, conditions
/// the frame on the initialisation *"of the controlling station"*). The
/// frame's own fields are the caller's too: the `COI` of 5-101 clause 7.2.6.21,
/// the ASDU's common address and the originator address, exactly as rule 6's
/// process image and rule 7's addressing are the caller's for
/// [`RedundancyGroup::send_user_data`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndInit {
    /// 10.3's condition: is data in the reverse direction defined for this
    /// station? False means no `ENDINIT.req` is issued at all.
    pub reverse_direction_data: bool,
    /// The `COI` the frame carries: clause 7.2.6.21's cause of initialisation.
    pub coi: Coi,
    /// The ASDU's common address.
    pub common_address: u16,
    /// The originator address.
    pub originator: u8,
}

/// What one timer expiry did to the group: the named connection's own reaction
/// and the switchover it triggered, if any.
///
/// 10.5 (index 128, printed 127) and 10.6 (index 132, printed 131) are the two
/// subsections this value belongs to; the group reports what it did rather than
/// switching over silently, and the caller performs the steps the standard
/// leaves to it (reopening the failed connection, the station interrogation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutOutcome {
    /// The named connection's own [`Session::on_timeout`] actions, unchanged and
    /// first on the wire: t1's active close (figures 17/18), t2's S-frame
    /// (clause 5.1) or t3's `TESTFR act` (clause 5.2). When the expiry was the
    /// group's switchover trigger, the close actions of every other member
    /// that is not stopped follow them (10.7's close rule), then the
    /// taking-over connection's `STARTDT act` and any user data it sends
    /// behind the act.
    pub actions: Vec<Action>,
    /// The switchover, when the expiry was the group's trigger: a `t1` on the
    /// started connection.
    pub switchover: Option<Switchover>,
}

/// A connection switchover as the value the group reports for it: 10.5's
/// *"a connection switchover will be performed (preferably automatic)"* (index
/// 128, printed 127) and 10.6's (index 132, printed 131).
///
/// The group starts *"one of the stopped connections … using the STARTDT
/// function"* itself, so this is a report and not a request. Rule 4's choice
/// (*"The controlling station decides which one of the N connections is be in
/// started state."*, index 118, printed 117) stays the caller's: a caller that
/// wants a particular connection performs the switchover through
/// [`RedundancyGroup::select`] and [`RedundancyGroup::start`] (10.2's manual
/// switchover) or stops the current one first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Switchover {
    /// The controlling station's automatic switchover. `failed` is the started
    /// connection whose `t1` expired (the one this call closed), `started` the
    /// stopped connection that took over and now carries the group's user data,
    /// and `unconfirmed` what the failed member holds for the replay.
    Automatic {
        /// The connection the failure was detected on.
        failed: usize,
        /// The stopped connection that was started to take over.
        started: usize,
        /// What the failed member holds for the replay
        /// ([`Member::left_behind`]): this connection's send buffer and the
        /// group's mirror of its clause 5.3 queue, plus what earlier failures
        /// of the member left and the application has not yet replayed or
        /// discarded.
        unconfirmed: usize,
    },
    /// The started connection failed but no other connection was both
    /// established and stopped, so none could be started: the group names no new
    /// connection, and holds the user data it is handed until one is named.
    /// 10.5 (index 128): *"reopening is regularly retried by the
    /// controlling station until the error has been corrected and the connection
    /// is re-established"*, and TS 60870-5-604 `5.4.13.20` (index 59, printed
    /// 58): *"The Controlling station tries at regular intervals to create a new
    /// Stopped connection for the now closed inoperable connection to the
    /// Controlled station."* Both are the caller's steps.
    NoStoppedConnection {
        /// The connection the failure was detected on.
        failed: usize,
        /// What the failed member holds for the replay
        /// ([`Member::left_behind`]): this connection's send buffer and the
        /// group's mirror of its clause 5.3 queue, plus what earlier failures
        /// of the member left and the application has not yet replayed or
        /// discarded.
        unconfirmed: usize,
    },
    /// A controlled station detects the same failure and performs no switchover
    /// of its own (rule 4, index 118: *"the selection and switchover of the
    /// started connection is always initiated by the controlling station"*). The
    /// group names no started connection and holds the user data it is handed
    /// until the naming moves, when the peer's `STARTDT_ACT` arrives on a stopped
    /// connection ([`RedundancyGroup::on_startdt_act`], 10.4, index 124), and
    /// 10.6's *"the pending event is retransmitted on this connection"* is
    /// [`RedundancyGroup::retransmit_unconfirmed`].
    LeftToTheControllingStation {
        /// The connection the failure was detected on.
        failed: usize,
        /// What the failed member holds for the replay
        /// ([`Member::left_behind`]): this connection's send buffer and the
        /// group's mirror of its clause 5.3 queue, plus what earlier failures
        /// of the member left and the application has not yet replayed or
        /// discarded.
        unconfirmed: usize,
    },
}

/// The application's decision on the data a failed connection had not
/// confirmed: 10.5 (index 128, printed 127), *"it is left to the application if
/// the ESDU is retransmitted"*.
///
/// The data the decision is about is everything the failed connection still
/// held: the frames in its send buffer and the group's mirror of its clause 5.3
/// queue, plus what earlier undecided failures of the same member left
/// ([`Member::left_behind`], [`RedundancyGroup::retransmit_unconfirmed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// Re-transmit the unconfirmed ASDUs on the group's started connection.
    ///
    /// *"In general, any unconfirmed user data will be retransmitted on the new
    /// started connection after a connection switchover has been performed"*
    /// (10.6, index 132, printed 131). One `Retransmit` per failure: a second
    /// call for the same member, with no new failure since, is
    /// [`GroupError::AlreadyRetransmitted`].
    Retransmit,
    /// Only count them: the call decides nothing, and the ASDUs stay kept for
    /// a later `Retransmit` or `Discard`, so it may be repeated.
    Leave,
    /// Drop them: *"terminating the ongoing application function and
    /// reinitiating it towards the new connection"* (10.5) is the caller's own
    /// step, and the group forgets the failed connection's data so that no
    /// later replay sends it after all.
    Discard,
}

/// What [`RedundancyGroup::retransmit_unconfirmed`] did, as a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// Nothing was re-sent and nothing was dropped: the member still holds
    /// `unconfirmed` ASDUs ([`Member::left_behind`]) for a later decision: the
    /// frames its failed connections never had confirmed and the ASDUs of their
    /// clause 5.3 queues, for every failure not yet replayed or discarded.
    Left {
        /// The ASDUs the member holds for the replay.
        unconfirmed: usize,
    },
    /// The held ASDUs were dropped ([`Replay::Discard`]).
    Discarded {
        /// How many there were.
        discarded: usize,
        /// The frames to put on the wire: the data the group held meanwhile,
        /// released onto the started connection
        /// ([`RedundancyGroup::held_user_data`]).
        actions: Vec<Action>,
    },
    /// The held ASDUs went out on the group's started connection, oldest first,
    /// re-stamped with that connection's own `N(S)`.
    Retransmitted {
        /// The frames to put on the wire.
        actions: Vec<Action>,
        /// How many of them the started connection could not put on the wire yet
        /// and holds in its own clause 5.3 queue.
        queued: usize,
    },
}

/// Why a redundancy-group operation was refused.
///
/// Every variant names the rule that was broken, so a caller can answer a peer
/// without reading the clause again. The layers below pass their own refusals
/// through rather than have them re-invented ([`GroupError::Queue`],
/// [`GroupError::Params`], [`GroupError::Layout`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupError {
    /// Rule 2: an empty member list is not one redundancy group. A group of
    /// zero logical connections has nothing to select and nothing to route.
    NoMembers,
    /// The index names no member of this group.
    MemberIndexOutOfRange {
        /// The index the caller used.
        index: usize,
        /// How many members the group has.
        members: usize,
    },
    /// Rule 3: no member of the group is the started connection, so no
    /// connection may carry user data.
    NoStartedConnection,
    /// Rule 3: the caller named a member that is not the started connection.
    /// Only one logical connection is in the started state at a time.
    NotStartedConnection {
        /// The member the caller named.
        index: usize,
    },
    /// Rule 4 and the 10.3/10.4 role split: a controlled station selects no
    /// connection, starts or stops none, issues no `ENDINIT.req` and runs no
    /// station interrogation of its own, and a controlling station does not take
    /// its naming from a received `STARTDT_ACT`. *"the selection and switchover of
    /// the started connection is always initiated by the controlling station"*
    /// (index 118).
    CannotSelect,
    /// The member's state does not allow the request: it is already in the
    /// state the caller asks for, or past it (a `start` on a connection that is
    /// not `Stopped`, a `close` on a terminated one). `state` is the member's
    /// own session state, which is the only place a connection state lives.
    AlreadyInState {
        /// The member the caller named.
        index: usize,
        /// Its state at the time of the call.
        state: State,
    },
    /// The member's session has no TCP connection: it was never established,
    /// or it was lost. A new session is [`State::Stopped`] too, so the state
    /// alone does not tell.
    NotConnected {
        /// The member the caller named.
        index: usize,
    },
    /// The connection refused the data: see [`QueueError`]. A terminated member
    /// cannot carry an ASDU, so the group does not hold it either; a full
    /// connection or group refuses it with [`QueueError::Full`].
    Queue(QueueError),
    /// 10.5's retransmission (index 128, printed 127): the connection the data
    /// came from is still the group's started one, so there is no new connection
    /// to re-send it on. The group does not duplicate a frame on the connection
    /// that already sent it.
    StillStartedConnection {
        /// The member the caller named.
        index: usize,
    },
    /// 10.5's retransmission (index 128, printed 127): what this member's
    /// failed connection left behind has already been replayed or discarded by
    /// a [`RedundancyGroup::retransmit_unconfirmed`] call, and nothing new is
    /// held, so the group never replays an ASDU twice. The next failure of the
    /// member holds new data.
    AlreadyRetransmitted {
        /// The member the caller named.
        index: usize,
    },
    /// The parameter set of a member is not admissible: see [`ParamError`].
    Params(ParamError),
    /// 10.3's `ENDINIT.req` could not be built: the layout layer's error,
    /// unchanged, exactly as the other two pass-throughs are. It cannot occur
    /// for the arguments [`EndInit`] carries (the cause and the information
    /// object address are [`end_of_initialisation`]'s, not the caller's), and
    /// it is propagated rather than unwrapped because nothing in `src/`
    /// panics.
    Layout(LayoutError),
}

impl From<LayoutError> for GroupError {
    fn from(err: LayoutError) -> Self {
        Self::Layout(err)
    }
}

/// One member's share of what a group call produced: the actions to perform on
/// that member's connection, in order.
///
/// The plain entry points ([`RedundancyGroup::start`],
/// [`RedundancyGroup::on_timeout`], …) return one merged list; a Start that
/// closes another connection puts that connection's close and the new one's
/// `STARTDT act` side by side. The `_at` entry points return this instead, so
/// each action reaches the socket it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routed {
    /// The member whose connection performs `actions`.
    pub member: usize,
    /// What that connection's session returned, in order.
    pub actions: Vec<Action>,
}

/// What [`RedundancyGroup::tick`] found due.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TickOutcome {
    /// The actions of every expired timer, per member, in order.
    pub routed: Vec<Routed>,
    /// The switchovers a failed started connection caused (10.5).
    pub switchovers: Vec<Switchover>,
    /// Controlling group: the members to dial now (never connected, or lost),
    /// with no attempt in flight or its t0 expired (clause 10.5's *"reopening
    /// is regularly retried"*; clause 10.7's t0 per connection). Report the
    /// outcome with [`RedundancyGroup::on_connection_established`] or, for a
    /// refused dial, [`RedundancyGroup::on_connection_lost`].
    pub connect: Vec<usize>,
}

/// The timer-aware, routed entry points: each takes the caller's clock, keeps
/// every member's [`Timers`] in step with what its session did (the same
/// wiring as [`crate::manager`], [`Supervisor`]) and returns [`Routed`]
/// actions. Driving a group through these and [`RedundancyGroup::tick`] is
/// all the timer handling a caller needs.
impl RedundancyGroup {
    /// Records one member's actions for the routed entry points.
    fn record(&mut self, index: usize, actions: &[Action]) {
        if actions.iter().any(|a| matches!(a, Action::ActiveClose(_))) {
            // The connection is over: what it leaves behind is taken now,
            // before anything else can move it.
            if let Some(member) = self.members.get_mut(index) {
                member.capture();
            }
        }
        if !actions.is_empty() {
            self.log.push((index, actions.to_vec()));
        }
    }

    /// Runs one plain entry point and applies what it did to every member's
    /// timers, returning its result and the routed actions.
    fn supervised<T>(
        &mut self,
        now: Instant,
        call: impl FnOnce(&mut Self) -> Result<T, GroupError>,
    ) -> Result<(T, Vec<Routed>), GroupError> {
        let before: Vec<Supervision> = self
            .members
            .iter()
            .map(|member| Supervision::of(&member.session))
            .collect();
        self.log.clear();
        let result = call(self);
        let log = std::mem::take(&mut self.log);
        for ((index, member), before) in self.members.iter_mut().enumerate().zip(before) {
            let actions: Vec<Action> = log
                .iter()
                .filter(|(at, _)| *at == index)
                .flat_map(|(_, actions)| actions.iter().cloned())
                .collect();
            member
                .supervisor
                .apply(&mut member.timers, &member.session, now, &actions, before);
        }
        let routed = log
            .into_iter()
            .map(|(member, actions)| Routed { member, actions })
            .collect();
        result.map(|value| (value, routed))
    }

    /// The caller's socket for member `index` came up: a fresh session
    /// (clause 5.1, 5.3) and fresh timers (only t3 armed).
    ///
    /// # Errors
    ///
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member.
    pub fn on_connection_established(
        &mut self,
        index: usize,
        now: Instant,
    ) -> Result<(), GroupError> {
        let member = self.member_mut(index)?;
        member.socket = true;
        // Whatever the previous connection left is taken before the fresh
        // session empties its buffers (clause 5.1): already, if its failure
        // was seen; now, if the caller re-establishes without reporting one.
        member.capture();
        member.captured = false;
        member.queued.clear();
        member.session.on_connection_established();
        // Nothing of an earlier connection is supervised on this one, also
        // when that connection's own session closed it and its timers were
        // never cleared by a loss (clause 5.1: a fresh connection).
        member.timers.connection_lost();
        member.timers.connection_established(now);
        member.supervisor = Supervisor::default();
        Ok(())
    }

    /// The caller's socket for member `index` went away, also when the
    /// member's own session had already closed it (a sequence error's active
    /// close). What the connection leaves behind is captured for the replay
    /// ([`Member::left_behind`]), unless its close already did. Everything else
    /// of that connection goes: its timers, and, for the started connection,
    /// the naming; user data is held until another is named, as after a
    /// failure. A controlling group dials it again when the t0 of the attempt
    /// it came from runs out: at the next tick after a connection that lasted
    /// longer than t0 (10.5's reopening), later after one lost sooner.
    ///
    /// A refused dial had no connection to lose: its t0 stays armed, so the
    /// retry comes at its expiry and not on every tick.
    ///
    /// # Errors
    ///
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member.
    pub fn on_connection_lost(&mut self, index: usize) -> Result<(), GroupError> {
        let controlling = self.role == Role::Controlling;
        let member = self.member_mut(index)?;
        member.capture();
        if !member.link_up() {
            // A refused dial, or a session the caller drives by hand that
            // closed itself: the naming goes with it all the same.
            if self.started == Some(index) {
                self.started = None;
                self.switching = true;
            }
            return Ok(());
        }
        member.socket = false;
        if member.session.is_connected() {
            member.session.on_connection_lost();
        }
        member.timers.connection_lost();
        member.supervisor = Supervisor::default();
        // Clause 10.5's reopening is "regularly retried": one attempt per t0,
        // as the connection manager does it, also when a peer takes every
        // connection and closes it at once. t0 is armed again from the attempt
        // this connection came from: due at once after a connection that
        // lasted longer, else when that t0 runs out.
        if controlling && let Some(began) = member.attempt_began {
            member.timers.connection_attempt(began);
        }
        if self.started == Some(index) {
            self.started = None;
            self.switching = true;
        }
        Ok(())
    }

    /// Feeds one codec error of one connection to that member's session, with
    /// the reactions of [`crate::link::reaction`]: a clause 5 violation closes
    /// the connection ([`Session::on_parse_error`]), and the framing conditions
    /// produce nothing. Going through the group matters for the close: what
    /// the connection leaves behind is captured for 10.5's replay
    /// ([`Member::left_behind`]), as for every other close. The started naming
    /// stays until the caller reports the loss
    /// ([`RedundancyGroup::on_connection_lost`]).
    ///
    /// # Errors
    ///
    /// [`GroupError::MemberIndexOutOfRange`] when `index` names no member.
    pub fn on_parse_error(
        &mut self,
        index: usize,
        error: ParseError,
    ) -> Result<Vec<Action>, GroupError> {
        let actions = self.member_mut(index)?.session_mut().on_parse_error(error);
        self.member_mut(index)?.note_wire(&actions);
        self.record(index, &actions);
        Ok(actions)
    }

    /// [`RedundancyGroup::on_parse_error`] at `now`, with that member's timers
    /// kept in step.
    ///
    /// # Errors
    ///
    /// As [`RedundancyGroup::on_parse_error`].
    pub fn on_parse_error_at(
        &mut self,
        index: usize,
        error: ParseError,
        now: Instant,
    ) -> Result<Vec<Routed>, GroupError> {
        Ok(self
            .supervised(now, |group| group.on_parse_error(index, error))?
            .1)
    }

    /// [`RedundancyGroup::on_frame`] at `now`: t3 is retriggered (and t2 armed
    /// for an I-frame) on that member before the frame is fed.
    ///
    /// # Errors
    ///
    /// As [`RedundancyGroup::on_frame`].
    pub fn on_frame_at(
        &mut self,
        index: usize,
        apci: Apci,
        now: Instant,
    ) -> Result<Vec<Routed>, GroupError> {
        let member = self.member_mut(index)?;
        member.timers.frame_received(now);
        if matches!(apci, Apci::I { .. }) {
            member.timers.i_frame_received(now);
        }
        Ok(self.supervised(now, |group| group.on_frame(index, apci))?.1)
    }

    /// [`RedundancyGroup::start`] at `now`.
    ///
    /// # Errors
    ///
    /// As [`RedundancyGroup::start`].
    pub fn start_at(&mut self, index: usize, now: Instant) -> Result<Vec<Routed>, GroupError> {
        Ok(self.supervised(now, |group| group.start(index))?.1)
    }

    /// [`RedundancyGroup::stop`] at `now`.
    ///
    /// # Errors
    ///
    /// As [`RedundancyGroup::stop`].
    pub fn stop_at(&mut self, index: usize, now: Instant) -> Result<Vec<Routed>, GroupError> {
        Ok(self.supervised(now, |group| group.stop(index))?.1)
    }

    /// [`RedundancyGroup::close`] at `now`.
    ///
    /// # Errors
    ///
    /// As [`RedundancyGroup::close`].
    pub fn close_at(&mut self, index: usize, now: Instant) -> Result<Vec<Routed>, GroupError> {
        Ok(self.supervised(now, |group| group.close(index))?.1)
    }

    /// [`RedundancyGroup::send_user_data`] at `now`. An empty result means the
    /// data is queued (on the connection, or by the group during a switchover).
    ///
    /// # Errors
    ///
    /// As [`RedundancyGroup::send_user_data`].
    pub fn send_user_data_at(
        &mut self,
        index: usize,
        asdu: &[u8],
        now: Instant,
    ) -> Result<Vec<Routed>, GroupError> {
        Ok(self
            .supervised(now, |group| group.send_user_data(index, asdu))?
            .1)
    }

    /// [`RedundancyGroup::retransmit_unconfirmed`] at `now`.
    ///
    /// # Errors
    ///
    /// As [`RedundancyGroup::retransmit_unconfirmed`].
    pub fn retransmit_unconfirmed_at(
        &mut self,
        failed: usize,
        replay: Replay,
        now: Instant,
    ) -> Result<(ReplayOutcome, Vec<Routed>), GroupError> {
        self.supervised(now, |group| group.retransmit_unconfirmed(failed, replay))
    }

    /// The soonest instant [`RedundancyGroup::tick`] has something to do, or
    /// `None` when nothing is armed: what an event loop sleeps until.
    ///
    /// The earliest of every member's timers that `tick` reacts to: t0 of a
    /// controlling group's member that is down (clause 10.7 sets t0 per
    /// connection), t0–t3 of one that is up and not [`State::Terminated`]. It
    /// is exact only right after a `tick`, which arms t0 for every member it
    /// asks to dial. A member whose loss was reported since, or a group that
    /// was never ticked, has a member with no t0 armed: it is due at once and
    /// has no instant here, so tick again after such an event instead of
    /// sleeping. A member whose session closed itself while its socket is still
    /// up has nothing due until the caller reports the loss.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        let controlling = self.role == Role::Controlling;
        self.members
            .iter()
            .filter_map(|member| {
                if member.link_up() {
                    // A connection its session closed does nothing until the
                    // caller reports the socket gone.
                    (member.state() != State::Terminated)
                        .then(|| member.timers.next_deadline())
                        .flatten()
                } else if controlling {
                    member.timers.deadline(Timer::T0)
                } else {
                    None
                }
            })
            .min()
    }

    /// Every member's expired timers at `now`, reacted to through
    /// [`RedundancyGroup::on_timeout`] (so a t1 on the started connection is
    /// 10.5's switchover) with the timers kept in step. For a controlling
    /// group it also arms t0 for, and lists in [`TickOutcome::connect`], every
    /// member that is down and has no attempt in flight or whose t0 expired.
    pub fn tick(&mut self, now: Instant) -> TickOutcome {
        let mut outcome = TickOutcome::default();
        for index in 0..self.members.len() {
            let Some(member) = self.members.get_mut(index) else {
                continue;
            };
            if member.link_up() && member.state() == State::Terminated {
                // Closed by its own session; the socket is still the caller's
                // to close, and nothing is dialed until it reports that.
                continue;
            }
            if !member.link_up() {
                // Clause 7.1: only the controlling station dials. One attempt
                // per member per t0, as the connection manager does it.
                if self.role == Role::Controlling
                    && member
                        .timers
                        .deadline(Timer::T0)
                        .is_none_or(|due| due <= now)
                {
                    member.timers.connection_attempt(now);
                    member.attempt_began = Some(now);
                    outcome.connect.push(index);
                }
                continue;
            }
            for timer in member.timers.expired(now) {
                if let Ok((timeout, routed)) =
                    self.supervised(now, |group| group.on_timeout(index, timer))
                {
                    outcome.routed.extend(routed);
                    outcome.switchovers.extend(timeout.switchover);
                }
            }
        }
        outcome
    }
}
