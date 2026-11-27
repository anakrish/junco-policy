//! Textual source injection with the unchanged native lock diagnostic context.
use crate::{Agent, PooledPath};
use history_store::{History, Store};
use junco_core::CompileError;
use junco_policy::{Action, LockEvent, LockPolicy};
use std::sync::Arc;

#[path = "../../benches/text/mod.rs"]
#[allow(dead_code)]
mod text;

/// Compiles authoritative text outside benchmark evaluation regions.
pub fn lock_policy(
    store: Arc<Store<LockEvent<Agent, PooledPath>>>,
) -> Result<LockPolicy<Agent, PooledPath>, CompileError> {
    let rules = text::load(
        text::LOCK_POLICY,
        &text::LockVocabulary {
            principal: |id| Agent(id as usize),
            resource: |id| PooledPath(id as usize),
        },
    );
    LockPolicy::from_rules(store, rules.try_into().expect("seven textual lock rules"))
}

/// Untimed differential preflight, including complete native denial text/fixes.
/// Reset events are recorded on original histories, not filtered to witnesses.
pub fn preflight() {
    let store = Arc::new(Store::new().unwrap());
    let mut actual = lock_policy(store.clone()).unwrap();
    let mut expected = LockPolicy::new(store.clone()).unwrap();
    let alphabet = [
        LockEvent::new(Agent(0), Action::Read, PooledPath(0)),
        LockEvent::new(Agent(1), Action::Read, PooledPath(0)),
        LockEvent::new(Agent(1), Action::Edit, PooledPath(0)),
        LockEvent::new(Agent(1), Action::Release, PooledPath(0)),
        LockEvent::new(Agent(0), Action::Remove, PooledPath(0)),
        LockEvent::new(Agent(1), Action::Release, PooledPath(1)),
    ];
    for length in 0..=3 {
        for mut word in 0..alphabet.len().pow(length) {
            let events = (0..length).map(|_| {
                let event = alphabet[word % alphabet.len()];
                word /= alphabet.len();
                event
            });
            let history = History::from_events(store.clone(), events).unwrap();
            for principal in [Agent(0), Agent(1)] {
                for action in [Action::Read, Action::Edit, Action::Release, Action::Remove] {
                    let candidate = LockEvent::new(principal, action, PooledPath(0));
                    assert_eq!(
                        actual.decide(&history, &candidate).unwrap(),
                        expected.decide(&history, &candidate).unwrap()
                    );
                }
            }
        }
    }
}

#[test]
fn textual_lock_matches_native_diagnostics() {
    preflight();
}
