#![cfg(feature = "runtime")]

#[path = "../examples/policies.rs"]
mod example_runner;

use example_runner::support;
use history_pipeline::{Limits, compile, parse};
use history_semantics::{PolicyDecision, TracePolicy, TraceRule};
use history_store::{History, Store};
use history_syntax::{
    AtomPattern, Comparison, Component, Component3, Component4, ComponentPattern, Event, Head,
    RegexExpr, Rule, RuleMode, TestExpr,
};
use std::sync::Arc;
use support::*;

const PRIOR: &str = include_str!("../examples/prior-edit.pipeline");
const LOCK: &str = include_str!("../examples/lock.pipeline");
const FLOW: &str = include_str!("../examples/flow.pipeline");

fn atom<E: Event>(
    coordinate: usize,
    comparison: Comparison,
    pattern: ComponentPattern<E::Component>,
) -> TestExpr<E> {
    TestExpr::atom(
        comparison,
        AtomPattern::new(Component::new(coordinate), pattern),
    )
}
fn var<E: Event>(coordinate: usize, name: &str, comparison: Comparison) -> TestExpr<E> {
    atom(coordinate, comparison, ComponentPattern::variable(name))
}
fn constant<E: Event>(
    coordinate: usize,
    value: E::Component,
    comparison: Comparison,
) -> TestExpr<E> {
    atom(coordinate, comparison, ComponentPattern::Constant(value))
}
fn action(value: u8, comparison: Comparison) -> TestExpr<LockEvent> {
    constant(1, Component3::C1(value), comparison)
}
fn lock_head(value: u8) -> Head<LockEvent> {
    Head::new([
        ComponentPattern::variable("p"),
        ComponentPattern::Constant(Component3::C1(value)),
        ComponentPattern::variable("r"),
    ])
}
fn native<E: Event + 'static>(
    store: Arc<Store<E>>,
    rules: Vec<(Rule<E>, &'static str, Vec<String>)>,
) -> TracePolicy<E> {
    TracePolicy::new(
        store,
        rules.into_iter().map(|(rule, message, fixes)| {
            TraceRule::new(rule, move |_| (message.into(), fixes.clone()))
        }),
    )
    .unwrap()
}
fn compare<E: Event + 'static>(
    store: Arc<Store<E>>,
    left: &mut TracePolicy<E>,
    right: &mut TracePolicy<E>,
    alphabet: &[E],
    candidates: &[E],
) {
    for length in 0..=3 {
        for mut word in 0..alphabet.len().pow(length) {
            let history = History::from_events(
                store.clone(),
                (0..length).map(|_| {
                    let event = alphabet[word % alphabet.len()];
                    word /= alphabet.len();
                    event
                }),
            )
            .unwrap();
            for candidate in candidates {
                let before = history.as_slice().to_vec();
                assert_eq!(
                    left.decide(&history, candidate).unwrap(),
                    right.decide(&history, candidate).unwrap(),
                    "{before:?}, {candidate:?}"
                );
                assert_eq!(history.as_slice(), before);
            }
        }
    }
}

#[test]
fn prior_edit_source_matches_existing_dsl_and_excludes_candidate() {
    let store = Arc::new(Store::new().unwrap());
    let mut parsed = compile(
        parse(PRIOR, &Lock, Limits::default()).unwrap(),
        store.clone(),
    )
    .unwrap();
    let tail = RegexExpr::concat([
        RegexExpr::All,
        RegexExpr::test(TestExpr::and([
            var(0, "p", Comparison::Eq),
            action(EDIT, Comparison::Eq),
            var(2, "r", Comparison::Eq),
        ])),
        RegexExpr::All,
    ]);
    let mut expected = native(
        store.clone(),
        vec![(
            Rule::new(RuleMode::Require, lock_head(RELEASE), tail),
            "Release requires an earlier matching edit.",
            vec![],
        )],
    );
    compare(
        store.clone(),
        &mut parsed,
        &mut expected,
        &[(1, EDIT, 9), (2, EDIT, 9), (1, EDIT, 8), (1, READ, 9)],
        &[(1, RELEASE, 9), (2, RELEASE, 9), (1, READ, 9)],
    );
    let source = PRIOR.replace("\"release\"", "\"edit\"");
    let mut parsed = compile(
        parse(&source, &Lock, Limits::default()).unwrap(),
        store.clone(),
    )
    .unwrap();
    let history = History::new(store).unwrap();
    assert!(matches!(
        parsed.decide(&history, &(1, EDIT, 9)).unwrap(),
        PolicyDecision::Deny { .. }
    ));
    assert!(history.as_slice().is_empty());
}

fn native_lock(store: Arc<Store<LockEvent>>) -> TracePolicy<LockEvent> {
    let foreign = |event_action| {
        TestExpr::and([
            var(0, "p", Comparison::Neq),
            action(event_action, Comparison::Eq),
            var(2, "r", Comparison::Eq),
        ])
    };
    let elsewhere = || var(2, "r", Comparison::Neq);
    let owner_stable = TestExpr::or([
        elsewhere(),
        TestExpr::and([
            action(EDIT, Comparison::Neq),
            action(RELEASE, Comparison::Neq),
            action(REMOVE, Comparison::Neq),
        ]),
    ]);
    // Independent factored stable predicates, as in the canonical lock DSL.
    let stale_stable = TestExpr::and([
        TestExpr::or([
            elsewhere(),
            TestExpr::and([
                action(EDIT, Comparison::Neq),
                action(REMOVE, Comparison::Neq),
            ]),
        ]),
        TestExpr::or([
            elsewhere(),
            action(READ, Comparison::Neq),
            var(0, "p", Comparison::Neq),
        ]),
    ]);
    let reader_stable = TestExpr::or([
        elsewhere(),
        TestExpr::and([
            action(READ, Comparison::Neq),
            action(REMOVE, Comparison::Neq),
        ]),
    ]);
    let active = |trigger, stable| {
        RegexExpr::concat([
            RegexExpr::All,
            RegexExpr::test(trigger),
            RegexExpr::star(RegexExpr::test(stable)),
        ])
    };
    let owner = active(foreign(EDIT), owner_stable);
    let stale = active(foreign(EDIT), stale_stable);
    let reader = active(foreign(READ), reader_stable);
    native(
        store,
        vec![
            (
                Rule::new(RuleMode::Forbid, lock_head(EDIT), owner.clone()),
                "owner",
                vec![],
            ),
            (
                Rule::new(RuleMode::Forbid, lock_head(RELEASE), owner.clone()),
                "owner",
                vec![],
            ),
            (
                Rule::new(RuleMode::Forbid, lock_head(REMOVE), owner),
                "owner",
                vec![],
            ),
            (
                Rule::new(RuleMode::Forbid, lock_head(EDIT), stale.clone()),
                "stale",
                vec!["read".into()],
            ),
            (
                Rule::new(RuleMode::Forbid, lock_head(REMOVE), stale),
                "stale",
                vec!["read".into()],
            ),
            (
                Rule::new(RuleMode::Forbid, lock_head(EDIT), reader.clone()),
                "reader",
                vec![],
            ),
            (
                Rule::new(RuleMode::Forbid, lock_head(REMOVE), reader),
                "reader",
                vec![],
            ),
        ],
    )
}

#[test]
fn seven_lock_rules_preserve_foreign_ownership_freshness_readers_and_original_resets() {
    let store = Arc::new(Store::new().unwrap());
    let mut parsed = compile(
        parse(LOCK, &Lock, Limits::default()).unwrap(),
        store.clone(),
    )
    .unwrap();
    let mut expected = native_lock(store.clone());
    compare(
        store.clone(),
        &mut parsed,
        &mut expected,
        &[
            (2, EDIT, 9),
            (2, RELEASE, 9),
            (1, READ, 9),
            (2, READ, 9),
            (1, REMOVE, 9),
            (2, EDIT, 8),
        ],
        &[
            (1, EDIT, 9),
            (1, RELEASE, 9),
            (1, REMOVE, 9),
            (1, READ, 9),
            (2, EDIT, 9),
        ],
    );
    let history = History::from_events(store.clone(), [(2, EDIT, 9), (2, RELEASE, 9)]).unwrap();
    assert_eq!(
        parsed.decide(&history, &(1, EDIT, 9)).unwrap(),
        PolicyDecision::Deny {
            failed_precondition: "stale".into(),
            allowed_fixes: vec!["read".into()]
        }
    );
    let history = History::from_events(store.clone(), [(2, READ, 9), (2, EDIT, 9)]).unwrap();
    assert_eq!(
        parsed.decide(&history, &(1, EDIT, 9)).unwrap(),
        PolicyDecision::Deny {
            failed_precondition: "owner".into(),
            allowed_fixes: vec![]
        }
    );
    let history = History::from_events(store, [(2, EDIT, 9), (1, REMOVE, 9)]).unwrap();
    assert_eq!(
        parsed.decide(&history, &(1, EDIT, 9)).unwrap(),
        PolicyDecision::Grant
    );
}

#[test]
fn information_flow_matches_existing_dsl_with_copy_local_declassification() {
    let store = Arc::new(Store::new().unwrap());
    let mut parsed = compile(
        parse(FLOW, &Flow, Limits::default()).unwrap(),
        store.clone(),
    )
    .unwrap();
    let trigger = TestExpr::and([
        var(0, "p", Comparison::Eq),
        var(1, "v", Comparison::Eq),
        constant(3, Component4::C3(0), Comparison::Eq),
        TestExpr::or([
            constant(2, Component4::C2(READ), Comparison::Eq),
            constant(2, Component4::C2(RECEIVE), Comparison::Eq),
        ]),
    ]);
    let stable = TestExpr::or([
        var(0, "p", Comparison::Neq),
        var(1, "v", Comparison::Neq),
        constant(3, Component4::C3(0), Comparison::Neq),
        constant(2, Component4::C2(DECLASSIFY), Comparison::Neq),
    ]);
    let rule = Rule::new(
        RuleMode::Forbid,
        Head::new([
            ComponentPattern::variable("p"),
            ComponentPattern::variable("v"),
            ComponentPattern::Constant(Component4::C2(CONTACT)),
            ComponentPattern::Constant(Component4::C3(1)),
        ]),
        RegexExpr::concat([
            RegexExpr::All,
            RegexExpr::test(trigger),
            RegexExpr::star(RegexExpr::test(stable)),
        ]),
    );
    let mut expected = native(
        store.clone(),
        vec![(
            rule,
            "This principal's copy of this handle is tainted.",
            vec!["Declassify this copy's untrusted label or use an untainted value.".into()],
        )],
    );
    compare(
        store.clone(),
        &mut parsed,
        &mut expected,
        &[
            (1, 9, READ, 0),
            (1, 9, RECEIVE, 0),
            (1, 9, DECLASSIFY, 0),
            (2, 9, DECLASSIFY, 0),
            (1, 8, DECLASSIFY, 0),
            (1, 9, DECLASSIFY, 1),
        ],
        &[
            (1, 9, CONTACT, 1),
            (2, 9, CONTACT, 1),
            (1, 8, CONTACT, 1),
            (1, 9, READ, 0),
        ],
    );
    let history = History::from_events(
        store,
        [(1, 9, READ, 0), (1, 9, DECLASSIFY, 0), (1, 9, RECEIVE, 0)],
    )
    .unwrap();
    assert!(matches!(
        parsed.decide(&history, &(1, 9, CONTACT, 1)).unwrap(),
        PolicyDecision::Deny { .. }
    ));
}

#[test]
fn operational_errors_are_not_grants() {
    let store = Arc::new(Store::new().unwrap());
    let other = Arc::new(Store::new().unwrap());
    let mut parsed = compile(parse(PRIOR, &Lock, Limits::default()).unwrap(), store).unwrap();
    let history = History::new(other).unwrap();
    assert_eq!(
        parsed.decide(&history, &(1, RELEASE, 9)),
        Err(junco_core::HistoryError::WrongHistoryOwner)
    );
}

#[test]
fn empty_never_any_composition_and_predicate_negation_are_distinct() {
    let store = Arc::new(Store::new().unwrap());
    let schema = "schema Lock(principal, action, resource);";
    for (language, empty, nonempty) in [
        ("History | empty", true, false),
        ("History | never", false, false),
        ("History | any", true, true),
        ("History | exists((Event))", false, true),
        ("History | exists((Event | where false))", false, false),
        ("History | exists((Event | where not(true)))", false, false),
        ("History | empty | complement", false, true),
        ("History | never | either (History | empty)", true, false),
        ("History | any | also (History | empty)", true, false),
        (
            "History | exists((Event | where not(action == \"edit\" or action == \"read\")))",
            false,
            true,
        ),
    ] {
        let source = format!("{schema} rule R = Candidate | require {language} | deny \"no\";");
        let mut policy = compile(
            parse(&source, &Lock, Limits::default()).unwrap(),
            store.clone(),
        )
        .unwrap();
        for (events, grant) in [(vec![], empty), (vec![(1, RELEASE, 9)], nonempty)] {
            let history = History::from_events(store.clone(), events).unwrap();
            assert_eq!(
                policy.decide(&history, &(1, EDIT, 9)).unwrap() == PolicyDecision::Grant,
                grant,
                "{language}"
            );
        }
    }
}

#[test]
fn typed_expansions_are_hygienic_and_accept_constants() {
    let source = r#"
        schema Lock(principal, action, resource);
        let Inner = (a:principal, b:principal, r:resource) {
            Event | where principal == a and principal != b and resource == r
        };
        let Outer = (b:principal, a:principal, r:resource) {
            History | exists(Inner(a, b, r))
        };
        let Selection = Candidate | bind principal=p, resource=r | where action == "release";
        let Alias = Selection;
        rule First = Alias | require Outer(2, p, r) | deny "first";
        rule Second = Alias | require History | never | deny "second";
    "#;
    let store = Arc::new(Store::new().unwrap());
    let mut policy = compile(
        parse(source, &Lock, Limits::default()).unwrap(),
        store.clone(),
    )
    .unwrap();
    let empty = History::new(store.clone()).unwrap();
    assert_eq!(
        policy.decide(&empty, &(1, RELEASE, 9)).unwrap(),
        PolicyDecision::Deny {
            failed_precondition: "first".into(),
            allowed_fixes: vec![]
        }
    );
    let history = History::from_events(store, [(1, READ, 9)]).unwrap();
    assert_eq!(
        policy.decide(&history, &(1, RELEASE, 9)).unwrap(),
        PolicyDecision::Deny {
            failed_precondition: "second".into(),
            allowed_fixes: vec![]
        }
    );
}

#[test]
fn algebra_singletons_zero_operand_identities_and_whole_language_negation_are_preserved() {
    let store = Arc::new(Store::new().unwrap());
    for (instructions, accepted_lengths) in [
        ("single (Event | where true);", vec![1]),
        ("single (Event | where false);", vec![]),
        ("single (Event | where true); negate;", vec![0, 2]),
        ("single (Event | where not(true));", vec![]),
        ("concat 0;", vec![0]),
        ("choice 0;", vec![]),
        ("intersection 0;", vec![0, 1, 2]),
        ("single (Event | where all_of());", vec![1]),
        ("single (Event | where any_of());", vec![]),
        (
            "single (Event | where true); single (Event | where true); concat 2;",
            vec![2],
        ),
        ("single (Event | where true); star;", vec![0, 1, 2]),
    ] {
        let source = format!(
            "schema Lock(principal,action,resource); rule R = Candidate | require History | algebra {{ {instructions} }} | deny \"x\";"
        );
        let mut policy = compile(
            parse(&source, &Lock, Limits::default()).unwrap(),
            store.clone(),
        )
        .unwrap();
        for length in 0..=2 {
            let history =
                History::from_events(store.clone(), std::iter::repeat_n((1, READ, 9), length))
                    .unwrap();
            assert_eq!(
                policy.decide(&history, &(1, READ, 9)).unwrap() == PolicyDecision::Grant,
                accepted_lengths.contains(&length),
                "{instructions}/{length}"
            );
        }
    }
}
