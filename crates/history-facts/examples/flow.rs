#[path = "support/flow.rs"]
mod flow;
use history_facts::{Limits, lower, parse};
use history_semantics::PolicyDecision;
use history_store::{History, Store};
use junco_policy::{FlowAction, FlowEvent};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let module = parse(include_str!("flow.facts"), Limits::default())?;
    let store = Arc::new(Store::new()?);
    let mut policy =
        lower(&module, &flow::FlowSchema, Limits::default())?.compile(store.clone())?;
    let event = |action, label| FlowEvent {
        principal: 0,
        handle: 0,
        action,
        label,
    };
    let mut history = History::from_events(store, [event(FlowAction::Receive, 0)])?;
    let candidate = event(FlowAction::Contact, 1);
    assert!(matches!(
        policy.decide(&history, &candidate)?,
        PolicyDecision::Deny { .. }
    ));
    history.push(event(FlowAction::Declassify, 0))?;
    assert_eq!(policy.decide(&history, &candidate)?, PolicyDecision::Grant);
    println!("Matching declassification reset the committed taint.");
    Ok(())
}
