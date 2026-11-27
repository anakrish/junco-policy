#[path = "support/lock.rs"]
mod lock;
use history_facts::{Limits, lower, parse};
use history_semantics::PolicyDecision;
use history_store::{History, Store};
use junco_policy::{Action, LockEvent};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let module = parse(include_str!("locks.facts"), Limits::default())?;
    let store = Arc::new(Store::new()?);
    let mut policy =
        lower(&module, &lock::LockSchema, Limits::default())?.compile(store.clone())?;
    let history = History::from_events(store, [LockEvent::new(1, Action::Edit, 0)])?;
    let candidate = LockEvent::new(0, Action::Edit, 0);
    assert!(matches!(policy.decide(&history, &candidate)?,
        PolicyDecision::Deny { failed_precondition, .. } if failed_precondition == "lock.owner"));
    println!("Foreign owner denied; the candidate was not recorded.");
    Ok(())
}
