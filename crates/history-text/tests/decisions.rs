#![cfg(feature = "runtime")]
#[path = "../examples/policies.rs"]
mod runnable;

use history_semantics::{PolicyDecision, TracePolicy, TraceRule};
use history_store::{History, Store};
use history_syntax::{
    AtomPattern, Comparison, Component, Component3, Component4, ComponentPattern, Event, Head,
    RegexExpr, Rule, RuleMode, TestExpr,
};
use history_text::{Limits, Resolver, Source, SourceId, compile, lower, parse};
use runnable::support::*;
use std::sync::Arc;

const PRIOR: &str = include_str!("../examples/prior-edit.junco");
const OWNER: &str = include_str!("../examples/owner-freshness.junco");
const FLOW: &str = include_str!("../examples/flow.junco");

fn variable<E: Event>(index: usize, name: &str, comparison: Comparison) -> TestExpr<E> {
    TestExpr::atom(
        comparison,
        AtomPattern::new(Component::new(index), ComponentPattern::variable(name)),
    )
}
fn constant<E: Event>(index: usize, value: E::Component, comparison: Comparison) -> TestExpr<E> {
    TestExpr::atom(
        comparison,
        AtomPattern::new(Component::new(index), ComponentPattern::Constant(value)),
    )
}
fn lock_action(value: u32, comparison: Comparison) -> TestExpr<Lock> {
    constant(1, Component3::C1(value), comparison)
}
fn lock_head(action: u32) -> Head<Lock> {
    Head::new([
        ComponentPattern::variable("p"),
        ComponentPattern::Constant(Component3::C1(action)),
        ComponentPattern::variable("r"),
    ])
}
fn prior_dsl() -> Vec<(&'static str, Rule<Lock>)> {
    vec![(
        "prior_edit",
        Rule::new(
            RuleMode::Require,
            lock_head(RELEASE),
            RegexExpr::concat([
                RegexExpr::All,
                RegexExpr::test(TestExpr::and([
                    variable(0, "p", Comparison::Eq),
                    lock_action(EDIT, Comparison::Eq),
                    variable(2, "r", Comparison::Eq),
                ])),
                RegexExpr::All,
            ]),
        ),
    )]
}
fn owner_dsl() -> Vec<(&'static str, Rule<Lock>)> {
    let foreign = TestExpr::and([
        variable(2, "r", Comparison::Eq),
        lock_action(EDIT, Comparison::Eq),
        variable(0, "p", Comparison::Neq),
    ]);
    let owned = TestExpr::or([
        variable(2, "r", Comparison::Neq),
        TestExpr::and([
            lock_action(EDIT, Comparison::Neq),
            lock_action(RELEASE, Comparison::Neq),
            lock_action(REMOVE, Comparison::Neq),
        ]),
    ]);
    let stable = TestExpr::and([
        TestExpr::or([
            variable(2, "r", Comparison::Neq),
            TestExpr::and([
                lock_action(EDIT, Comparison::Neq),
                lock_action(REMOVE, Comparison::Neq),
            ]),
        ]),
        TestExpr::or([
            variable(2, "r", Comparison::Neq),
            lock_action(READ, Comparison::Neq),
            variable(0, "p", Comparison::Neq),
        ]),
    ]);
    vec![
        (
            "foreign_owner",
            Rule::new(
                RuleMode::Forbid,
                lock_head(EDIT),
                RegexExpr::concat([
                    RegexExpr::All,
                    RegexExpr::test(foreign.clone()),
                    RegexExpr::star(RegexExpr::test(owned)),
                ]),
            ),
        ),
        (
            "stale_view",
            Rule::new(
                RuleMode::Forbid,
                lock_head(EDIT),
                RegexExpr::concat([
                    RegexExpr::All,
                    RegexExpr::test(foreign),
                    RegexExpr::star(RegexExpr::test(stable)),
                ]),
            ),
        ),
    ]
}
fn flow_action(value: u32, comparison: Comparison) -> TestExpr<Flow> {
    constant(2, Component4::C2(value), comparison)
}
fn flow_dsl() -> Vec<(&'static str, Rule<Flow>)> {
    let head = Head::new([
        ComponentPattern::variable("p"),
        ComponentPattern::variable("v"),
        ComponentPattern::Constant(Component4::C2(CONTACT)),
        ComponentPattern::Constant(Component4::C3(20)),
    ]);
    let taint = TestExpr::and([
        variable(0, "p", Comparison::Eq),
        variable(1, "v", Comparison::Eq),
        TestExpr::or([
            flow_action(READ, Comparison::Eq),
            flow_action(RECEIVE, Comparison::Eq),
        ]),
        constant(3, Component4::C3(10), Comparison::Eq),
    ]);
    let kept = TestExpr::or([
        variable(0, "p", Comparison::Neq),
        variable(1, "v", Comparison::Neq),
        flow_action(DECLASSIFY, Comparison::Neq),
        constant(3, Component4::C3(10), Comparison::Neq),
    ]);
    vec![(
        "no_tainted_contact",
        Rule::new(
            RuleMode::Forbid,
            head,
            RegexExpr::concat([
                RegexExpr::All,
                RegexExpr::test(taint),
                RegexExpr::star(RegexExpr::test(kept)),
            ]),
        ),
    )]
}
fn textual<E: Event + 'static, R: Resolver<E>>(
    text: &str,
    resolver: &R,
    store: Arc<Store<E>>,
) -> TracePolicy<E>
where
    R::Error: std::fmt::Debug,
{
    let parsed = parse(
        Source {
            id: SourceId(1),
            text,
        },
        Limits::default(),
    )
    .unwrap();
    let typed = lower(&parsed, resolver).unwrap();
    compile(
        typed,
        store,
        Arc::new(|info, _| (info.name.clone(), Vec::new())),
    )
    .unwrap()
}

fn differential<E: Event + 'static, R: Resolver<E>>(
    text: &str,
    resolver: &R,
    expected: Vec<(&'static str, Rule<E>)>,
    alphabet: &[E],
    candidates: &[E],
) where
    R::Error: std::fmt::Debug,
{
    let store = Arc::new(Store::new().unwrap());
    let mut actual = textual(text, resolver, store.clone());
    let mut expected = TracePolicy::new(
        store.clone(),
        expected
            .into_iter()
            .map(|(name, rule)| TraceRule::new(rule, move |_| (name.to_string(), Vec::new()))),
    )
    .unwrap();
    for length in 0..=3 {
        for mut word in 0..alphabet.len().pow(length) {
            let events = (0..length)
                .map(|_| {
                    let event = alphabet[word % alphabet.len()];
                    word /= alphabet.len();
                    event
                })
                .collect::<Vec<_>>();
            let history = History::from_events(store.clone(), events).unwrap();
            for candidate in candidates {
                let decision = expected.decide(&history, candidate).unwrap();
                assert_eq!(
                    actual.decide(&history, candidate).unwrap(),
                    decision,
                    "{history:?} {candidate:?}"
                );
                assert_eq!(
                    actual.decide(&history, candidate).unwrap(),
                    decision,
                    "warm {history:?} {candidate:?}"
                );
            }
        }
    }
}

#[test]
fn source_to_existing_dsl_differential_prior_owner_and_flow() {
    differential(
        PRIOR,
        &LockVocabulary,
        prior_dsl(),
        &[
            (1, EDIT, 7),
            (2, EDIT, 7),
            (1, EDIT, 8),
            (1, READ, 7),
            (1, RELEASE, 7),
        ],
        &[(1, RELEASE, 7), (2, RELEASE, 7), (1, EDIT, 7)],
    );
    differential(
        OWNER,
        &LockVocabulary,
        owner_dsl(),
        &[
            (2, EDIT, 7),
            (2, RELEASE, 7),
            (1, READ, 7),
            (2, READ, 7),
            (1, REMOVE, 7),
            (1, EDIT, 7),
            (2, REMOVE, 8),
        ],
        &[(1, EDIT, 7), (2, EDIT, 7), (1, READ, 7)],
    );
    differential(
        FLOW,
        &FlowVocabulary,
        flow_dsl(),
        &[
            (1, 7, READ, 10),
            (1, 7, RECEIVE, 10),
            (1, 7, DECLASSIFY, 10),
            (2, 7, DECLASSIFY, 10),
            (1, 8, DECLASSIFY, 10),
            (1, 7, DECLASSIFY, 11),
        ],
        &[
            (1, 7, CONTACT, 20),
            (2, 7, CONTACT, 20),
            (1, 7, CONTACT, 10),
        ],
    );
}

fn outcome<E: Event + 'static>(
    policy: &mut TracePolicy<E>,
    store: &Arc<Store<E>>,
    events: &[E],
    candidate: E,
) -> Option<String> {
    let history = History::from_events(store.clone(), events.iter().copied()).unwrap();
    let before = history.as_slice().to_vec();
    let decision = policy.decide(&history, &candidate).unwrap();
    assert_eq!(history.as_slice(), before);
    match decision {
        PolicyDecision::Grant => None,
        PolicyDecision::Deny {
            failed_precondition,
            ..
        } => Some(failed_precondition),
    }
}

#[test]
fn prior_edit_candidate_exclusion_and_complete_original_history() {
    let store = Arc::new(Store::new().unwrap());
    let mut prior = textual(PRIOR, &LockVocabulary, store.clone());
    let q = (1, RELEASE, 7);
    for history in [vec![], vec![(2, EDIT, 7)], vec![(1, EDIT, 8)], vec![q]] {
        assert_eq!(
            outcome(&mut prior, &store, &history, q).as_deref(),
            Some("prior_edit")
        );
    }
    assert_eq!(
        outcome(
            &mut prior,
            &store,
            &[(1, READ, 8), (1, EDIT, 7), (2, READ, 8)],
            q
        ),
        None
    );
    assert_eq!(outcome(&mut prior, &store, &[], (1, READ, 7)), None);
    let text = PRIOR.replace("action == action.edit", "action == action.release");
    let mut candidate_test = textual(&text, &LockVocabulary, store.clone());
    assert_eq!(
        outcome(&mut candidate_test, &store, &[], q).as_deref(),
        Some("prior_edit")
    );
}

#[test]
fn reset_events_are_not_filtered_and_first_violation_is_ordered() {
    let store = Arc::new(Store::new().unwrap());
    let mut owner = textual(OWNER, &LockVocabulary, store.clone());
    let q = (1, EDIT, 7);
    assert_eq!(outcome(&mut owner, &store, &[], q), None);
    assert_eq!(
        outcome(&mut owner, &store, &[(2, EDIT, 7)], q).as_deref(),
        Some("foreign_owner")
    );
    assert_eq!(
        outcome(&mut owner, &store, &[(2, EDIT, 7), (2, RELEASE, 7)], q).as_deref(),
        Some("stale_view")
    );
    assert_eq!(
        outcome(&mut owner, &store, &[(2, EDIT, 7), (2, RELEASE, 8)], q).as_deref(),
        Some("foreign_owner")
    );
    assert_eq!(
        outcome(
            &mut owner,
            &store,
            &[(2, EDIT, 7), (2, RELEASE, 7), (2, READ, 7)],
            q
        )
        .as_deref(),
        Some("stale_view")
    );
    assert_eq!(
        outcome(
            &mut owner,
            &store,
            &[(2, EDIT, 7), (2, RELEASE, 7), (1, READ, 7)],
            q
        ),
        None
    );
    assert_eq!(
        outcome(&mut owner, &store, &[(2, EDIT, 7), (1, REMOVE, 7)], q),
        None
    );
    let mut reversed = owner_dsl();
    reversed.reverse();
    let mut reversed = TracePolicy::new(
        store.clone(),
        reversed
            .into_iter()
            .map(|(name, rule)| TraceRule::new(rule, move |_| (name.to_string(), Vec::new()))),
    )
    .unwrap();
    assert_eq!(
        outcome(&mut reversed, &store, &[(2, EDIT, 7)], q).as_deref(),
        Some("stale_view")
    );
    let parsed = parse(
        Source {
            id: SourceId(1),
            text: OWNER,
        },
        Limits::default(),
    )
    .unwrap();
    let typed = lower::<Lock, _>(&parsed, &LockVocabulary).unwrap();
    let spans = typed
        .entries()
        .iter()
        .map(|entry| entry.info.span)
        .collect::<Vec<_>>();
    let swapped = format!(
        "junco 1; schema \"lock/1\"; policy p {{ rule {} rule {} }}",
        &OWNER[spans[1].start..spans[1].end],
        &OWNER[spans[0].start..spans[0].end]
    );
    let mut swapped = textual(&swapped, &LockVocabulary, store.clone());
    assert_eq!(
        outcome(&mut swapped, &store, &[(2, EDIT, 7)], q).as_deref(),
        Some("stale_view")
    );
    let all_then_deny = "junco 1; schema \"lock/1\"; policy p {
        rule satisfied { candidate { principal: $p, action: $a, resource: $r }; require all; }
        rule violation { candidate { principal: $p, action: $a, resource: $r }; forbid all; }}";
    let mut ordered = textual(all_then_deny, &LockVocabulary, store.clone());
    assert_eq!(
        outcome(&mut ordered, &store, &[], q).as_deref(),
        Some("violation")
    );
}

#[test]
fn flow_reset_is_principal_handle_label_local_and_receive_retaints() {
    let store = Arc::new(Store::new().unwrap());
    let mut flow = textual(FLOW, &FlowVocabulary, store.clone());
    let q = (1, 7, CONTACT, 20);
    let taint = (1, 7, READ, 10);
    assert_eq!(outcome(&mut flow, &store, &[], q), None);
    for wrong in [
        (2, 7, DECLASSIFY, 10),
        (1, 8, DECLASSIFY, 10),
        (1, 7, DECLASSIFY, 11),
    ] {
        assert_eq!(
            outcome(&mut flow, &store, &[taint, wrong], q).as_deref(),
            Some("no_tainted_contact")
        );
    }
    let reset = (1, 7, DECLASSIFY, 10);
    assert_eq!(outcome(&mut flow, &store, &[taint, reset], q), None);
    assert_eq!(
        outcome(&mut flow, &store, &[taint, reset, (1, 7, RECEIVE, 10)], q).as_deref(),
        Some("no_tainted_contact")
    );
    assert_eq!(outcome(&mut flow, &store, &[(2, 7, READ, 10)], q), None);
    assert_eq!(outcome(&mut flow, &store, &[(1, 8, READ, 10)], q), None);
}

#[test]
fn native_empty_epsilon_all_test_complement_and_polarity() {
    let store = Arc::new(Store::<Lock>::new().unwrap());
    for (tail, accepted) in [
        ("all", [true, true, true]),
        ("empty", [false, false, false]),
        ("epsilon", [true, false, false]),
        ("event { true }", [false, true, false]),
        ("event { false }*", [true, false, false]),
        ("!event { true }", [true, false, true]),
        ("event { action != action.edit }", [false, true, false]),
        ("epsilon | event { true } & all >> all", [true, true, false]),
    ] {
        for mode in ["require", "forbid"] {
            let text = format!("junco 1; schema \"lock/1\"; policy p {{
                rule r {{ candidate {{ principal: $p, action: $a, resource: $r }}; {mode} {tail}; }} }}");
            let mut policy = textual(&text, &LockVocabulary, store.clone());
            for (length, &accepts) in accepted.iter().enumerate() {
                let history = vec![(1, READ, 7); length];
                let denied = outcome(&mut policy, &store, &history, (1, EDIT, 7)).is_some();
                assert_eq!(
                    denied,
                    if mode == "require" { !accepts } else { accepts },
                    "{mode} {tail} {length}"
                );
            }
        }
    }
}

#[test]
fn operational_history_errors_remain_errors() {
    let store = Arc::new(Store::<Lock>::new().unwrap());
    let other = Arc::new(Store::<Lock>::new().unwrap());
    let mut policy = textual(PRIOR, &LockVocabulary, store);
    let foreign_history = History::from_events(other, [(1, EDIT, 7)]).unwrap();
    assert!(policy.decide(&foreign_history, &(1, RELEASE, 7)).is_err());
}
