#[path = "../tests/support/mod.rs"]
pub(crate) mod support;

use history_semantics::PolicyDecision;
use history_store::{History, Store};
use history_text::{Limits, Source, SourceId, compile, lower, parse};
use std::sync::Arc;
use support::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = |text| Source {
        id: SourceId(1),
        text,
    };
    let render =
        Arc::new(|info: &history_text::RuleInfo, _: &Lock| (info.name.clone(), Vec::new()));
    let store = Arc::new(Store::<Lock>::new()?);
    let parsed = parse(source(include_str!("prior-edit.junco")), Limits::default())?;
    let mut prior = compile(
        lower(&parsed, &LockVocabulary)?,
        store.clone(),
        render.clone(),
    )?;
    let empty = History::new(store.clone())?;
    assert!(matches!(
        prior.decide(&empty, &(1, RELEASE, 7))?,
        PolicyDecision::Deny { .. }
    ));
    let edited = History::from_events(store.clone(), [(1, EDIT, 7)])?;
    assert_eq!(
        prior.decide(&edited, &(1, RELEASE, 7))?,
        PolicyDecision::Grant
    );

    let parsed = parse(
        source(include_str!("owner-freshness.junco")),
        Limits::default(),
    )?;
    let mut owner = compile(lower(&parsed, &LockVocabulary)?, store.clone(), render)?;
    let released = History::from_events(store.clone(), [(2, EDIT, 7), (2, RELEASE, 7)])?;
    assert!(matches!(owner.decide(&released, &(1, EDIT, 7))?,
        PolicyDecision::Deny { failed_precondition, .. } if failed_precondition == "stale_view"));
    let refreshed = History::from_events(store, [(2, EDIT, 7), (2, RELEASE, 7), (1, READ, 7)])?;
    assert_eq!(
        owner.decide(&refreshed, &(1, EDIT, 7))?,
        PolicyDecision::Grant
    );

    let store = Arc::new(Store::<Flow>::new()?);
    let parsed = parse(source(include_str!("flow.junco")), Limits::default())?;
    let mut flow = compile(
        lower(&parsed, &FlowVocabulary)?,
        store.clone(),
        Arc::new(|info, _: &Flow| (info.name.clone(), Vec::new())),
    )?;
    let tainted = History::from_events(store.clone(), [(1, 7, RECEIVE, 10)])?;
    assert!(matches!(
        flow.decide(&tainted, &(1, 7, CONTACT, 20))?,
        PolicyDecision::Deny { .. }
    ));
    let reset = History::from_events(store, [(1, 7, RECEIVE, 10), (1, 7, DECLASSIFY, 10)])?;
    assert_eq!(
        flow.decide(&reset, &(1, 7, CONTACT, 20))?,
        PolicyDecision::Grant
    );
    println!("prior-edit, ownership/freshness and flow/reset examples passed");
    Ok(())
}

#[test]
fn runnable_examples() {
    main().unwrap();
}
