//! Protocol parameters and their standard defaults.
//!
//! Every value here comes from the standard's own parameter tables:
//!
//! - IEC 60870-5-104:2006 clauses 5.4 and 9: port number 2404 ("The server
//!   (controlled station) uses the port number 2404 in all cases, both for the
//!   listening port and the established connections").
//! - Clause 5.5: k ("The transmitter stops the transmission at k
//!   unacknowledged I format APDUs"), maximum range of k and w: 1 to 32767
//!   APDUs, and k shall never exceed n − 1 for modulo n operation.
//! - Clause 9's interoperability list gives the defaults and permitted ranges
//!   of the time-outs, of k (maximum number of outstanding I format APDUs) and
//!   of w (latest acknowledge APDUs):
//!
//!   ```text
//!   t0  30 s   time-out of connection establishment
//!   t1  15 s   time-out of send or test APDUs
//!   t2  10 s   time-out for acknowledges in case of no data messages, t2 < t1
//!   t3  20 s   time-out for sending test frames in case of a long idle state
//!   k   12 APDUs
//!   w    8 APDUs   (recommendation: w should not exceed two-thirds of k)
//!   ```
//!
//!   Maximum range for time-outs t0 to t2: 1 s to 255 s, accuracy 1 s.
//!   Recommended range for time-out t3: 1 s to 48 h, resolution 1 s.

use core::time::Duration;

/// Sequence-number modulus of the 15-bit control-field counters.
pub const MODULUS: u32 = 32768;

/// The standard port number (clause 5.4).
pub const PORT: u16 = 2404;

/// Largest permitted k (clause 5.5: `n − 1` for modulo n operation).
pub const K_MAX: u16 = 32_767;

/// Largest permitted w (clause 5.5: maximum range 1 to 32767 APDUs).
pub const W_MAX: u16 = K_MAX;

/// Maximum permitted value of the time-outs t0 … t2 (clause 9, 1 s … 255 s).
pub const T_MAX: Duration = Duration::from_secs(255);

/// Upper bound of the recommended range for t3 (clause 9, 1 s … 48 h).
pub const T3_RECOMMENDED_MAX: Duration = Duration::from_secs(48 * 60 * 60);

/// Link parameters of one connection, with the standard's defaults.
///
/// The defaults are the ones the interoperability list marks "default value";
/// a real project overrides them per station ("selected value").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkParams {
    /// TCP port. The controlled station listens here; 2404 in all cases.
    pub port: u16,
    /// k: the maximum number of sequentially numbered I-format APDUs the DTE
    /// may have outstanding (unacknowledged) at a given time.
    pub k: u16,
    /// w: the receiver acknowledges at the latest after receiving w I-format
    /// APDUs.
    pub w: u16,
    /// t0: time-out of connection establishment.
    pub t0: Duration,
    /// t1: time-out of send or test APDUs (a sent U- or I-frame).
    pub t1: Duration,
    /// t2: time-out for acknowledges in case of no data messages.
    pub t2: Duration,
    /// t3: time-out for sending test frames in case of a long idle state.
    pub t3: Duration,
}

impl Default for LinkParams {
    fn default() -> Self {
        Self {
            port: PORT,
            k: 12,
            w: 8,
            t0: Duration::from_secs(30),
            t1: Duration::from_secs(15),
            t2: Duration::from_secs(10),
            t3: Duration::from_secs(20),
        }
    }
}

/// Why a [`LinkParams`] set is not admissible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamError {
    /// k outside 1 ..= 32767.
    KOutOfRange(u16),
    /// w outside 1 ..= 32767.
    WOutOfRange(u16),
    /// t0, t1 or t2 outside the 1 s … 255 s maximum range.
    TimeoutOutOfRange {
        /// Which time-out: `"t0"`, `"t1"` or `"t2"`.
        which: &'static str,
        /// Its value in whole seconds.
        secs: u64,
    },
    /// The table states t2 < t1.
    T2NotLessThanT1 {
        /// t1 in whole seconds.
        t1: u64,
        /// t2 in whole seconds.
        t2: u64,
    },
    /// t3 outside its recommended range (1 s … 48 h).
    T3OutOfRecommendedRange(u64),
}

impl LinkParams {
    /// Checks the normative constraints of clauses 5.5 and 9.
    ///
    /// `t3` is only checked against its *recommended* range, which is why it
    /// gets the last, separate error.
    ///
    /// # Errors
    ///
    /// The [`ParamError`] naming the first parameter out of its range.
    pub fn validate(&self) -> Result<(), ParamError> {
        if self.k == 0 || self.k > K_MAX {
            return Err(ParamError::KOutOfRange(self.k));
        }
        if self.w == 0 || self.w > W_MAX {
            return Err(ParamError::WOutOfRange(self.w));
        }
        for (which, t) in [("t0", self.t0), ("t1", self.t1), ("t2", self.t2)] {
            if t.is_zero() || t > T_MAX {
                return Err(ParamError::TimeoutOutOfRange {
                    which,
                    secs: t.as_secs(),
                });
            }
        }
        if self.t2 >= self.t1 {
            return Err(ParamError::T2NotLessThanT1 {
                t1: self.t1.as_secs(),
                t2: self.t2.as_secs(),
            });
        }
        if self.t3.is_zero() || self.t3 > T3_RECOMMENDED_MAX {
            return Err(ParamError::T3OutOfRecommendedRange(self.t3.as_secs()));
        }
        Ok(())
    }

    /// True when the clause-5.5 recommendation `w <= 2/3 k` is honoured.
    ///
    /// A recommendation, not a requirement: a violating set is still legal.
    #[must_use]
    pub fn w_within_recommendation(&self) -> bool {
        3 * u32::from(self.w) <= 2 * u32::from(self.k)
    }

    /// Maximum window size for the sequence numbers: k can never exceed
    /// `n − 1` (clause 5.5), i.e. the modulus minus one.
    #[must_use]
    pub const fn max_k() -> u16 {
        K_MAX
    }
}
