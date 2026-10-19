//! The server's send queue: one first-in first-out queue per row of 5-101
//! Table 16, emptied highest row first.

use std::collections::VecDeque;

use iec104::asdu::{AddressSizes, Header};
use iec104::gi::Scope;
use iec104::tx::{Priority, append_objects, respond_priority};

/// Something waiting to be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// An ASDU, encoded. `event` marks an event the application reported,
    /// which the event buffer's limit applies to.
    Frame { asdu: Vec<u8>, event: bool },
    /// The running interrogation, whose data is encoded from the image when
    /// the entry is taken and then waits as an [`Item::Answer`].
    Interrogation,
    /// The data of the running interrogation of `scope` not handed over yet,
    /// then its termination. Dropped when the procedure stops it.
    Answer {
        scope: Scope,
        frames: VecDeque<Vec<u8>>,
    },
    /// The data and termination of the running counter interrogation, taken
    /// the same way.
    CounterInterrogation,
    /// A received read command, answered from the image when it is handed
    /// over.
    Read(Vec<u8>),
}

const ROWS: usize = 6;

#[derive(Debug)]
pub struct Queue {
    rows: [VecDeque<Item>; ROWS],
    sizes: AddressSizes,
    /// The most events kept; the oldest is dropped for a new one beyond it.
    limit: usize,
    /// Events waiting now.
    events: usize,
    /// Events dropped for room since the start.
    pub dropped: u64,
}

impl Queue {
    pub fn new(sizes: AddressSizes, limit: usize) -> Self {
        Self {
            rows: Default::default(),
            sizes,
            limit,
            events: 0,
            dropped: 0,
        }
    }

    /// The row of `priority`, highest first.
    const fn row(&mut self, priority: Priority) -> &mut VecDeque<Item> {
        let [init, command, event, request, interrogation, cyclic] = &mut self.rows;
        match priority {
            Priority::EndOfInitialisation => init,
            Priority::Command => command,
            Priority::Event => event,
            Priority::Request => request,
            Priority::Interrogation => interrogation,
            Priority::Cyclic => cyclic,
        }
    }

    /// Queues an encoded ASDU in its row.
    pub fn frame(&mut self, asdu: Vec<u8>) {
        let priority = self.priority_of(&asdu);
        self.row(priority)
            .push_back(Item::Frame { asdu, event: false });
    }

    /// Queues an event the application reported, dropping the oldest such
    /// event when the buffer is full (TS 60870-5-604 5.4.16.1's local buffer
    /// has a size; what it does when full is the station's own).
    pub fn event(&mut self, asdu: Vec<u8>) {
        let priority = self.priority_of(&asdu);
        if self.limit == 0 {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        if self.events >= self.limit {
            for queue in &mut self.rows {
                if let Some(at) = queue
                    .iter()
                    .position(|item| matches!(item, Item::Frame { event: true, .. }))
                {
                    queue.remove(at);
                    self.events = self.events.saturating_sub(1);
                    self.dropped = self.dropped.saturating_add(1);
                    break;
                }
            }
        }
        self.events = self.events.saturating_add(1);
        self.row(priority)
            .push_back(Item::Frame { asdu, event: true });
    }

    /// Queues `item` in `priority`'s row.
    pub fn push(&mut self, priority: Priority, item: Item) {
        self.row(priority).push_back(item);
    }

    /// Queues `item` at the head of `priority`'s row.
    pub fn push_front(&mut self, priority: Priority, item: Item) {
        self.row(priority).push_front(item);
    }

    /// Drops every interrogation answer whose scope `stopped` names.
    pub fn drop_answers(&mut self, stopped: impl Fn(Scope) -> bool) {
        for queue in &mut self.rows {
            queue.retain(|item| !matches!(item, Item::Answer { scope, .. } if stopped(*scope)));
        }
    }

    /// Puts frames back at the head of their rows, in their order: the rest
    /// of an entry that stands for several, or a frame whose hand-over
    /// failed.
    pub fn put_back(&mut self, frames: Vec<Vec<u8>>) {
        for asdu in frames.into_iter().rev() {
            let priority = self.priority_of(&asdu);
            self.row(priority)
                .push_front(Item::Frame { asdu, event: false });
        }
    }

    /// The head of the highest row that has one.
    ///
    /// An event takes the events right behind it in its row along into one
    /// ASDU while [`append_objects`] allows it: TS 60870-5-604 5.4.16.1,
    /// *"The Controlled station transmits events of the same Type, COT and
    /// priority but with gaps in their addresses as a Set of Information
    /// elements (SQ:=0) in one single ASDU, filled until the maximum
    /// configured ASDU or ADPU length as in the PICS"*. Only consecutive
    /// events are joined, so the order on the wire is the order reported
    /// (5-101 cl.7.2.2.2), and the row is the same, so Table 16's order is
    /// untouched. Events that found the window open went out alone; it is the
    /// ones that waited for it that share an ASDU.
    pub fn pop(&mut self) -> Option<Item> {
        let Self {
            rows,
            sizes,
            events,
            ..
        } = self;
        let queue = rows.iter_mut().find(|queue| !queue.is_empty())?;
        let item = queue.pop_front()?;
        let Item::Frame {
            mut asdu,
            event: true,
        } = item
        else {
            return Some(item);
        };
        *events = events.saturating_sub(1);
        while let Some(Item::Frame {
            asdu: next,
            event: true,
        }) = queue.front()
        {
            if !append_objects(&mut asdu, next, *sizes) {
                break;
            }
            queue.pop_front();
            *events = events.saturating_sub(1);
        }
        Some(Item::Frame { asdu, event: true })
    }

    pub fn is_empty(&self) -> bool {
        self.rows.iter().all(VecDeque::is_empty)
    }

    fn priority_of(&self, asdu: &[u8]) -> Priority {
        // Every ASDU queued here was built by this crate, so it parses; one
        // that did not would be an answer to a request.
        Header::parse_with(asdu, self.sizes)
            .map_or(Priority::Request, |header| respond_priority(&header))
    }
}
