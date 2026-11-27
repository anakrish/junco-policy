pub(crate) mod support;

use history_pipeline::{Limits, compile, parse};
use history_semantics::PolicyDecision;
use history_store::{History, Store};
use std::{error::Error, sync::Arc};
use support::*;

fn main() -> Result<(), Box<dyn Error>> {
    let store = Arc::new(Store::<LockEvent>::new()?);
    let mut history = History::new(store.clone())?;
    let mut prior = compile(
        parse(
            include_str!("prior-edit.pipeline"),
            &Lock,
            Limits::default(),
        )?,
        store.clone(),
    )?;
    let release = (1, RELEASE, 9);
    assert!(matches!(
        prior.decide(&history, &release)?,
        PolicyDecision::Deny { .. }
    ));
    history.push((1, EDIT, 9))?;
    assert_eq!(prior.decide(&history, &release)?, PolicyDecision::Grant);

    let mut lock = compile(
        parse(include_str!("lock.pipeline"), &Lock, Limits::default())?,
        store,
    )?;
    assert!(matches!(
        lock.decide(&history, &(2, EDIT, 9))?,
        PolicyDecision::Deny { .. }
    ));

    let store = Arc::new(Store::<FlowEvent>::new()?);
    let mut history = History::new(store.clone())?;
    let mut flow = compile(
        parse(include_str!("flow.pipeline"), &Flow, Limits::default())?,
        store,
    )?;
    history.push((1, 9, READ, 0))?;
    assert!(matches!(
        flow.decide(&history, &(1, 9, CONTACT, 1))?,
        PolicyDecision::Deny { .. }
    ));
    history.push((1, 9, DECLASSIFY, 0))?;
    assert_eq!(
        flow.decide(&history, &(1, 9, CONTACT, 1))?,
        PolicyDecision::Grant
    );
    println!("Prior-edit, seven-rule lock, and declassification examples passed.");
    Ok(())
}

#[test]
fn runnable_examples() {
    main().unwrap();
}
