//! DNS workers may run under the forwarder's settings read lock. Reserve a slot and
//! post to the engine's existing queue; never wait for the engine or the gate here.
use super::Event;
use crate::dns_forwarder::{DeliveredDns, DeliveredDnsHook};
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    mpsc::Sender,
    Arc,
};

const LIMIT: usize = 64;

#[derive(Default)]
pub(super) struct Ingress {
    // Even generations accept records. An odd generation has a reset awaiting the engine.
    generation: AtomicU64,
    pending: AtomicUsize,
    latest_epoch: AtomicU64,
}

pub(super) struct Record {
    owner: Arc<Ingress>,
    generation: u64,
    pub dns: DeliveredDns,
}

impl Record {
    pub fn current(&self) -> bool {
        self.generation == self.owner.generation.load(Ordering::Acquire)
    }
}

impl Drop for Record {
    fn drop(&mut self) {
        self.owner.pending.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(super) struct Loss {
    owner: Arc<Ingress>,
    generation: u64,
}

impl Loss {
    pub fn resume(self) -> u64 {
        let _ = self.owner.generation.compare_exchange(
            self.generation,
            self.generation.wrapping_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.owner.latest_epoch.load(Ordering::Acquire)
    }
}

pub(super) fn hook(tx: Sender<Event>) -> DeliveredDnsHook {
    let owner = Arc::new(Ingress::default());
    Box::new(move |dns| {
        owner.latest_epoch.fetch_max(dns.epoch, Ordering::AcqRel);
        let generation = owner.generation.load(Ordering::Acquire);
        if generation & 1 != 0 {
            return;
        }
        if owner.pending.fetch_add(1, Ordering::AcqRel) >= LIMIT {
            owner.pending.fetch_sub(1, Ordering::AcqRel);
            let lost = generation.wrapping_add(1);
            if owner
                .generation
                .compare_exchange(generation, lost, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let _ = tx.send(Event::DnsCompatibilityLoss(Loss {
                    owner: owner.clone(),
                    generation: lost,
                }));
            }
        } else {
            let _ = tx.send(Event::DnsDelivered(Record {
                owner: owner.clone(),
                generation,
                dns,
            }));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_forwarder::DeliveredDnsKind;

    fn answer(epoch: u64) -> DeliveredDns {
        DeliveredDns {
            epoch,
            started_at_ms: 1,
            observed_at_ms: 2,
            name: "ordinary.example".into(),
            kind: DeliveredDnsKind::Ipv4,
            qtype: 1,
            incomplete: false,
            scope_known: false,
            values: vec![],
        }
    }

    #[test]
    fn overflow_invalidates_pending_records_once_and_recovers_in_the_current_epoch() {
        let (tx, rx) = std::sync::mpsc::channel();
        let submit = hook(tx);
        for _ in 0..=LIMIT {
            submit(answer(3));
        }
        submit(answer(4));
        for _ in 0..LIMIT {
            let Event::DnsDelivered(record) = rx.try_recv().unwrap() else {
                panic!("expected queued answer")
            };
            assert!(!record.current());
        }
        let Event::DnsCompatibilityLoss(loss) = rx.try_recv().unwrap() else {
            panic!("expected one reset")
        };
        assert!(rx.try_recv().is_err());
        assert_eq!(loss.resume(), 4);
        submit(answer(4));
        let Event::DnsDelivered(record) = rx.try_recv().unwrap() else {
            panic!("expected current answer")
        };
        assert!(record.current());
    }
}
