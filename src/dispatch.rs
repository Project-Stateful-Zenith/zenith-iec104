//! Which procedure a received ASDU belongs to.
//!
//! Every procedure module classifies the frames it owns and answers the rest
//! as not its own. A caller that offered one ASDU to every module would
//! therefore get several answers, and for a frame with an unknown field, one
//! clause 7.2.3 mirror from each. [`route`] names the one module an ASDU is
//! for, from its type identification and, for monitor-direction data, its
//! cause of transmission. [`not_implemented`] is the single answer for a
//! control-direction type no module serves.
//!
//! ```
//! use iec104::asdu::{Cause, Header, TypeId};
//! use iec104::dispatch::{route, Route};
//!
//! let header = |type_id, cause| Header {
//!     type_id,
//!     sequence: false,
//!     count: 1,
//!     cause,
//!     negative: false,
//!     test: false,
//!     originator: 0,
//!     common_address: 1,
//! };
//! assert_eq!(route(&header(TypeId::CIcNa1, Cause::Activation)), Route::Interrogation);
//! // Monitor data goes where its cause says it came from.
//! assert_eq!(
//!     route(&header(TypeId::MMeNb1, Cause::InterrogatedByStation)),
//!     Route::Interrogation
//! );
//! assert_eq!(route(&header(TypeId::MMeNb1, Cause::Spontaneous)), Route::Transmission);
//! assert_eq!(route(&header(TypeId::MSpNa1, Cause::ReturnInfoRemote)), Route::Command);
//! ```

use crate::asdu::{
    AddressSizes, Cause, Direction, Header, TypeId, Unspecified, is_mirror, mirror_frame,
};
use crate::{ct, ft, pm, ts};

/// The procedure module that owns an ASDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// [`crate::init`]: `M_EI_NA_1`, the end of initialisation.
    Init,
    /// [`crate::gi`]: `C_IC_NA_1`, and monitor data with causes 20–36.
    Interrogation,
    /// [`crate::ci`]: `C_CI_NA_1`, and integrated totals with causes 37–41.
    CounterInterrogation,
    /// [`crate::cs`]: `C_CS_NA_1`.
    ClockSync,
    /// [`crate::ct`]: the fourteen command types, and return information
    /// (causes 11 and 12).
    Command,
    /// [`crate::rd`]: `C_RD_NA_1`, and monitor data with cause 5.
    Read,
    /// [`crate::pm`]: the parameter types (outside an interrogation response).
    Parameter,
    /// [`crate::ts`]: `C_TS_NA_1` and `C_TS_TA_1`.
    Test,
    /// [`crate::ft`]: the file-transfer types `<120>`–`<127>`.
    FileTransfer,
    /// [`crate::tx`]: monitor data with causes 1, 2 and 3.
    Transmission,
    /// Monitor-direction data with a cause no procedure receives: 101
    /// cl.7.2.3 discards it (and may log it).
    Discard,
    /// A type no module serves: `C_RP_NA_1`, `C_CD_NA_1`, or a reserved or
    /// private type. A controlled station answers it with [`not_implemented`].
    NotImplemented,
}

/// The one procedure `header`'s ASDU belongs to.
///
/// Control-direction types go to their procedure whatever the cause, so its
/// confirmations, terminations and 44–47 mirrors reach the station that sent
/// the request. Monitor-direction data goes where its cause says it came
/// from: an interrogation, a counter interrogation, a read, a command's return
/// information, or cyclic, background or spontaneous transmission.
#[must_use]
pub fn route(header: &Header) -> Route {
    let type_id = header.type_id;
    if ct::is_command_type(type_id) {
        return Route::Command;
    }
    if ts::is_test_type(type_id) {
        return Route::Test;
    }
    if ft::is_file_type(type_id) {
        return Route::FileTransfer;
    }
    match type_id {
        TypeId::MEiNa1 => return Route::Init,
        TypeId::CIcNa1 => return Route::Interrogation,
        TypeId::CCiNa1 => return Route::CounterInterrogation,
        TypeId::CRdNa1 => return Route::Read,
        TypeId::CCsNa1 => return Route::ClockSync,
        _ => {}
    }
    if pm::is_parameter_type(type_id) {
        // Parameters of measured values may be reported in a station or group
        // interrogation response (101 cl.7.3.5.1–7.3.5.3, causes 20 to 36).
        return match header.cause {
            Cause::InterrogatedByStation | Cause::InterrogatedByGroup(_) => Route::Interrogation,
            _ => Route::Parameter,
        };
    }
    if type_id.direction() != Some(Direction::Monitor) {
        return Route::NotImplemented;
    }
    match header.cause {
        Cause::InterrogatedByStation | Cause::InterrogatedByGroup(_) => Route::Interrogation,
        Cause::RequestedByGeneralCounter | Cause::RequestedByCounterGroup(_) => {
            Route::CounterInterrogation
        }
        Cause::Request => Route::Read,
        Cause::ReturnInfoRemote | Cause::ReturnInfoLocal => Route::Command,
        Cause::Periodic | Cause::BackgroundScan | Cause::Spontaneous => Route::Transmission,
        _ => Route::Discard,
    }
}

/// A controlled station's answer to a [`Route::NotImplemented`] ASDU.
///
/// This is clause 7.2.3's cause-44 mirror (unknown type identification) with
/// the station's own `common_address`. It is `None` when nothing is to be sent:
/// the ASDU is itself a mirror, or it travelled in the monitor direction
/// (which a controlling station discards).
#[must_use]
pub fn not_implemented(
    header: &Header,
    asdu: &[u8],
    common_address: u16,
    sizes: AddressSizes,
) -> Option<Vec<u8>> {
    if is_mirror(header) || header.type_id.direction() == Some(Direction::Monitor) {
        return None;
    }
    Some(mirror_frame(
        header,
        asdu,
        Unspecified::TypeIdentification,
        common_address,
        sizes,
    ))
}
