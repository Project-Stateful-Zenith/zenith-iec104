//! The latest value of every point a station sent, kept from the updates.
//!
//! See [`ProcessImage`] and the section "Process image" of the client's
//! module documentation for why the application feeds it.

use std::collections::BTreeMap;

use iec104::asdu::{Asdu, Cause, Point};
use tokio::time::Instant;

use super::Update;

/// What a [`ProcessImage`] holds for one address: the latest point, the
/// cause it was sent with and when it arrived.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ImageEntry {
    /// The value, its quality and its time tag, as
    /// [`Objects::points`](iec104::asdu::Objects::points) gives them. A value
    /// with `IV` set is kept like any other; its quality says so.
    pub point: Point,
    /// The cause of transmission of the ASDU that carried it: spontaneous,
    /// interrogated, periodic, requested, return information and so on
    /// (5-101 cl.7.2.3).
    pub cause: Cause,
    /// The instant the application passed to [`ProcessImage::apply`] (or
    /// [`ProcessImage::apply_asdu`]) with it.
    pub arrived: Instant,
}

/// The latest value of each point a controlled station sent, by common
/// address and information object address.
///
/// It is the controlling station's "network image" that 5-101 cl.7.4.5 has
/// the station interrogation synchronise (*"The station interrogation is used to synchronize the
/// process information of the controlling station (network image NIM) and
/// the controlled stations."*).
///
/// The application feeds it the [`Update`]s of [`Client::subscribe`]
/// (interrogation data, spontaneous and cyclic changes, read answers alike),
/// and each value replaces the one stored for its address. The last to
/// arrive wins, since the station sends them in order. 5-101 cl.7.2.2.2:
/// *"the requirement that all values reported for a particular information
/// object are in correct chronological order must be observed."*
///
/// It holds only addresses the station sent, one entry each, and nothing
/// else: its size is bounded by the station's own address space, not by the
/// number of updates. Nothing is removed on its own, a lost connection
/// included; [`ImageEntry::arrived`] tells how old a value is, and
/// [`ProcessImage::clear`] empties it.
///
/// Not stored:
/// - ASDUs with the test bit set. 5-101 cl.7.2.3: *"the test-bit defines
///   ASDUs which were generated during test conditions. It is used for
///   example to test transmission and equipment without controlling the
///   process."* They are not the process's state.
/// - Types that carry no process value
///   ([`Objects::points`](iec104::asdu::Objects::points) gives none: end of
///   initialisation, the confirmations of commands and system commands,
///   parameters, file transfer), and [`Update::Undecodable`] ASDUs.
///
/// ```no_run
/// use iec104_tokio::TcpConnector;
/// use iec104_tokio::client::{Client, ClientConfig, ProcessImage};
/// use tokio::time::Instant;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let connector = TcpConnector::new(vec!["192.0.2.10:2404".into()]);
/// // Subscribe before the start, so the interrogation run on it is seen.
/// let client = Client::spawn(connector, ClientConfig::new(1))?;
/// let mut updates = client.subscribe().await?;
/// client.wait_started().await?;
///
/// let mut image = ProcessImage::new();
/// while let Some(update) = updates.recv().await {
///     image.apply(&update, Instant::now());
///     if let Some(entry) = image.get(1, 100) {
///         println!("{:?} ({:?})", entry.point.value, entry.point.quality);
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// [`Client::subscribe`]: super::Client::subscribe
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcessImage {
    entries: BTreeMap<(u16, u32), ImageEntry>,
}

impl ProcessImage {
    /// An empty image.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores the points of an [`Update::Data`] with `arrived` as their
    /// arrival, and returns how many it stored. Every other update stores
    /// nothing.
    pub fn apply(&mut self, update: &Update, arrived: Instant) -> usize {
        match update {
            Update::Data(asdu) => self.apply_asdu(asdu, arrived),
            _ => 0,
        }
    }

    /// Stores the points of one decoded ASDU, as [`ProcessImage::apply`]
    /// does. For ASDUs obtained elsewhere, such as the result of
    /// [`Client::interrogate`](super::Client::interrogate) or
    /// [`Client::read`](super::Client::read) (which the subscribers also
    /// receive).
    pub fn apply_asdu(&mut self, asdu: &Asdu, arrived: Instant) -> usize {
        if asdu.header.test {
            return 0;
        }
        let common_address = asdu.header.common_address;
        let cause = asdu.header.cause;
        let points = asdu.objects.points();
        let stored = points.len();
        for point in points {
            self.entries.insert(
                (common_address, point.ioa),
                ImageEntry {
                    point,
                    cause,
                    arrived,
                },
            );
        }
        stored
    }

    /// The latest entry for `ioa` at `common_address`, if the station sent
    /// one.
    #[must_use]
    pub fn get(&self, common_address: u16, ioa: u32) -> Option<&ImageEntry> {
        self.entries.get(&(common_address, ioa))
    }

    /// Every entry, ordered by common address, then information object
    /// address.
    pub fn iter(&self) -> impl Iterator<Item = ((u16, u32), &ImageEntry)> {
        self.entries.iter().map(|(&key, entry)| (key, entry))
    }

    /// How many addresses the image holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the image holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Forgets every entry.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}
