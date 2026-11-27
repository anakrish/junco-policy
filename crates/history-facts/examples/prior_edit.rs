#[path = "support/lock.rs"]
mod lock;

use history_facts::{Limits, lower, parse};
use history_semantics::PolicyDecision;
use history_store::{History, Store};
use junco_policy::{Action, LockEvent};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = include_str!("prior_edit.facts");
    let module = parse(source, Limits::default())?;
    let lowered = lower(&module, &lock::LockSchema, Limits::default())?;
    println!(
        "{}: {}",
        lowered.obligations[0].metadata.name, lowered.obligations[0].metadata.report
    );
    let store = Arc::new(Store::new()?);
    let mut history = History::new(store.clone())?;
    let mut policy = lowered.compile(store)?;
    let candidate = LockEvent::new(0, Action::Release, 0);
    assert!(matches!(
        policy.decide(&history, &candidate)?,
        PolicyDecision::Deny { .. }
    ));
    history.push(LockEvent::new(0, Action::Edit, 0))?;
    assert_eq!(policy.decide(&history, &candidate)?, PolicyDecision::Grant);
    assert_eq!(history.as_slice().len(), 1);
    Ok(())
}
