#![cfg(feature = "runtime")]

#[path = "../examples/support/flow.rs"]
mod flow;
#[path = "../examples/support/lock.rs"]
mod lock;
use history_facts::{Limits, lower, parse};
use history_semantics::{CompiledRule, PolicyDecision, TracePolicy};
use history_store::{History, Store};
use history_syntax::{
    AtomPattern, Comparison as C, Component, ComponentPattern as P, Head, RegexExpr as R, Rule,
    RuleMode, TestExpr as T,
};
use junco_policy::{
    Action, FlowAction, FlowComponent as FC, FlowEvent, FlowPolicy, FlowRule, LockComponent as LC,
    LockEvent, LockPolicy,
};
use std::sync::Arc;

type LE = LockEvent<u8, u8>;
type FE = FlowEvent<u8, u8, u8>;

fn l(p: u8, action: Action, r: u8) -> LE {
    LockEvent::new(p, action, r)
}
fn f(p: u8, v: u8, action: FlowAction, label: u8) -> FE {
    FlowEvent {
        principal: p,
        handle: v,
        action,
        label,
    }
}

fn atom<E: history_syntax::Event>(i: usize, cmp: C, pattern: P<E::Component>) -> T<E> {
    T::atom(cmp, AtomPattern::new(Component::new(i), pattern))
}
fn lock_action(action: Action, cmp: C) -> T<LE> {
    atom(1, cmp, P::constant(LC::Action(action)))
}
fn lock_var(i: usize, cmp: C) -> T<LE> {
    atom(i, cmp, P::variable(if i == 0 { "p" } else { "r" }))
}
fn lock_head(action: Action) -> Head<LE> {
    Head::new([
        P::variable("p"),
        P::constant(LC::Action(action)),
        P::variable("r"),
    ])
}

fn manual_prior() -> Rule<LE> {
    Rule::new(
        RuleMode::Require,
        lock_head(Action::Release),
        R::concat([
            R::All,
            R::test(T::and([
                lock_var(0, C::Eq),
                lock_var(2, C::Eq),
                lock_action(Action::Edit, C::Eq),
            ])),
            R::All,
        ]),
    )
}

fn manual_locks() -> Vec<Rule<LE>> {
    let setter = |action| {
        T::and([
            lock_var(2, C::Eq),
            lock_action(action, C::Eq),
            lock_var(0, C::Neq),
        ])
    };
    let stable = |actions: &[Action]| {
        T::or([
            lock_var(2, C::Neq),
            T::and(actions.iter().map(|&a| lock_action(a, C::Neq))),
        ])
    };
    let owner = R::concat([
        R::All,
        R::Test(setter(Action::Edit)),
        R::star(R::Test(stable(&[
            Action::Edit,
            Action::Release,
            Action::Remove,
        ]))),
    ]);
    let stale = R::concat([
        R::All,
        R::Test(setter(Action::Edit)),
        R::star(R::Test(T::and([
            stable(&[Action::Edit, Action::Remove]),
            T::or([
                lock_var(2, C::Neq),
                lock_action(Action::Read, C::Neq),
                lock_var(0, C::Neq),
            ]),
        ]))),
    ]);
    let reader = R::concat([
        R::All,
        R::Test(setter(Action::Read)),
        R::star(R::Test(stable(&[Action::Read, Action::Remove]))),
    ]);
    [
        (Action::Edit, owner.clone()),
        (Action::Release, owner.clone()),
        (Action::Remove, owner),
        (Action::Edit, stale.clone()),
        (Action::Remove, stale),
        (Action::Edit, reader.clone()),
        (Action::Remove, reader),
    ]
    .into_iter()
    .map(|(a, tail)| Rule::new(RuleMode::Forbid, lock_head(a), tail))
    .collect()
}

fn manual_flow() -> Rule<FE> {
    let var = |i, cmp| atom(i, cmp, P::variable(if i == 0 { "p" } else { "v" }));
    let action = |a, cmp| atom(2, cmp, P::constant(FC::Action(a)));
    let label = |cmp| atom(3, cmp, P::constant(FC::Label(0)));
    Rule::new(
        RuleMode::Forbid,
        Head::new([
            P::variable("p"),
            P::variable("v"),
            P::constant(FC::Action(FlowAction::Contact)),
            P::constant(FC::Label(1)),
        ]),
        R::concat([
            R::All,
            R::Test(T::and([
                var(0, C::Eq),
                var(1, C::Eq),
                label(C::Eq),
                T::or([
                    action(FlowAction::Read, C::Eq),
                    action(FlowAction::Receive, C::Eq),
                ]),
            ])),
            R::star(R::Test(T::or([
                var(0, C::Neq),
                var(1, C::Neq),
                action(FlowAction::Declassify, C::Neq),
                label(C::Neq),
            ]))),
        ]),
    )
}

fn traces<E: Copy>(alphabet: &[E], max: usize, mut visit: impl FnMut(&[E])) {
    let mut levels = vec![Vec::new()];
    visit(&[]);
    for _ in 0..max {
        let mut next = Vec::new();
        for prefix in &levels {
            for &event in alphabet {
                let mut trace = prefix.clone();
                trace.push(event);
                visit(&trace);
                next.push(trace);
            }
        }
        levels = next;
    }
}

fn lock_diagnostic(decision: PolicyDecision) -> Option<String> {
    match decision {
        PolicyDecision::Grant => None,
        PolicyDecision::Deny {
            failed_precondition,
            ..
        } => Some(failed_precondition),
    }
}

#[test]
fn prior_edit_source_matches_existing_dsl_including_candidate_exclusion() {
    let module = parse(
        include_str!("../examples/prior_edit.facts"),
        Limits::default(),
    )
    .unwrap();
    let source = lower(&module, &lock::LockSchema, Limits::default()).unwrap();
    let store = Arc::new(Store::new().unwrap());
    let mut parsed = CompiledRule::new(store.clone(), source.obligations[0].rule.clone()).unwrap();
    let mut manual = CompiledRule::new(store.clone(), manual_prior()).unwrap();
    let mut policy = source.compile(store.clone()).unwrap();
    let alphabet = [
        l(0, Action::Edit, 0),
        l(1, Action::Edit, 0),
        l(0, Action::Edit, 1),
        l(0, Action::Read, 0),
        l(0, Action::Release, 0),
    ];
    traces(&alphabet, 3, |events| {
        let history = History::from_events(store.clone(), events.iter().copied()).unwrap();
        for candidate in alphabet {
            let actual = parsed.accepts_history(&history, &candidate).unwrap();
            assert_eq!(
                actual,
                manual.accepts_history(&history, &candidate).unwrap(),
                "{events:?} {candidate:?}"
            );
            if candidate.action == Action::Release {
                let witness = events.iter().any(|e| {
                    e.principal == candidate.principal
                        && e.resource == candidate.resource
                        && e.action == Action::Edit
                });
                assert_eq!(actual, Some(witness));
                assert_eq!(
                    policy.decide(&history, &candidate).unwrap() == PolicyDecision::Grant,
                    witness
                );
            } else {
                assert_eq!(actual, None);
            }
        }
        assert_eq!(history.as_slice(), events);
    });
    let own_witness = "language junco.facts.v1; package exclusion; schema lock;
        policy x ordered { require r on {principal: p, action: action.edit, resource: r}
        if { exists e in history { e.principal == p; e.resource == r; e.action == action.edit; }; }
        report prior.edit_required; }";
    let source = lower(
        &parse(own_witness, Limits::default()).unwrap(),
        &lock::LockSchema,
        Limits::default(),
    )
    .unwrap();
    let mut policy = source.compile(store.clone()).unwrap();
    let empty = History::new(store).unwrap();
    assert!(matches!(
        policy.decide(&empty, &l(0, Action::Edit, 0)).unwrap(),
        PolicyDecision::Deny { .. }
    ));
    assert!(empty.as_slice().is_empty());
}

#[test]
fn seven_lock_rules_match_dsl_builtin_and_original_history_reference() {
    let module = parse(include_str!("../examples/locks.facts"), Limits::default()).unwrap();
    let source = lower(&module, &lock::LockSchema, Limits::default()).unwrap();
    let store = Arc::new(Store::new().unwrap());
    let mut parsed: Vec<_> = source
        .obligations
        .iter()
        .map(|o| CompiledRule::new(store.clone(), o.rule.clone()).unwrap())
        .collect();
    let mut manual: Vec<_> = manual_locks()
        .into_iter()
        .map(|r| CompiledRule::new(store.clone(), r).unwrap())
        .collect();
    let mut policy = source.compile(store.clone()).unwrap();
    let mut builtin = LockPolicy::new(store.clone()).unwrap();
    let alphabet = [
        l(0, Action::Read, 0),
        l(1, Action::Read, 0),
        l(0, Action::Edit, 0),
        l(1, Action::Edit, 0),
        l(1, Action::Release, 0),
        l(1, Action::Remove, 0),
        l(1, Action::Edit, 1),
        l(1, Action::Remove, 1),
    ];
    let candidates = [
        l(0, Action::Read, 0),
        l(0, Action::Edit, 0),
        l(0, Action::Release, 0),
        l(0, Action::Remove, 0),
    ];
    traces(&alphabet, 3, |events| {
        let history = History::from_events(store.clone(), events.iter().copied()).unwrap();
        let mut owner = None;
        let mut reader = None;
        let mut stale = false;
        for event in events.iter().filter(|e| e.resource == 0) {
            match event.action {
                Action::Edit => {
                    owner = Some(event.principal);
                    stale = event.principal != 0;
                }
                Action::Read => {
                    reader = Some(event.principal);
                    if event.principal == 0 {
                        stale = false;
                    }
                }
                Action::Release => owner = None,
                Action::Remove => {
                    owner = None;
                    reader = None;
                    stale = false;
                }
            }
        }
        for candidate in candidates {
            let mut first = None;
            for (i, (a, b)) in parsed.iter_mut().zip(&mut manual).enumerate() {
                let answer = a.accepts_history(&history, &candidate).unwrap();
                assert_eq!(
                    answer,
                    b.accepts_history(&history, &candidate).unwrap(),
                    "rule {i}: {events:?}"
                );
                if answer == Some(true) && first.is_none() {
                    first = Some(i);
                }
            }
            let expected = if candidate.action == Action::Read {
                None
            } else if owner.is_some_and(|p| p != 0) {
                Some("lock.owner")
            } else if candidate.action == Action::Release {
                None
            } else if stale {
                Some("lock.stale")
            } else if reader.is_some_and(|p| p != 0) {
                Some("lock.reader")
            } else {
                None
            };
            let selected = first.map(|i| {
                if i < 3 {
                    "lock.owner"
                } else if i < 5 {
                    "lock.stale"
                } else {
                    "lock.reader"
                }
            });
            assert_eq!(selected, expected, "{events:?} {candidate:?}");
            let actual = lock_diagnostic(policy.decide(&history, &candidate).unwrap());
            assert_eq!(actual.as_deref(), expected);
            let native = lock_diagnostic(builtin.decide(&history, &candidate).unwrap());
            let native_key = native.as_deref().map(|text| {
                if text.contains("is owned by") {
                    "lock.owner"
                } else if text.contains("was modified") {
                    "lock.stale"
                } else {
                    assert!(text.contains("was last read"));
                    "lock.reader"
                }
            });
            assert_eq!(native_key, expected);
        }
        assert_eq!(history.as_slice(), events);
    });
}

#[test]
fn flow_source_matches_dsl_builtin_and_strictly_later_reset_reference() {
    let module = parse(include_str!("../examples/flow.facts"), Limits::default()).unwrap();
    let source = lower(&module, &flow::FlowSchema, Limits::default()).unwrap();
    let store = Arc::new(Store::new().unwrap());
    let mut parsed = CompiledRule::new(store.clone(), source.obligations[0].rule.clone()).unwrap();
    let mut manual = CompiledRule::new(store.clone(), manual_flow()).unwrap();
    let mut policy = source.compile(store.clone()).unwrap();
    let builtin = FlowPolicy::new().rule(FlowRule::no_contact_after_read(0, &[1]));
    let alphabet = [
        f(0, 0, FlowAction::Read, 0),
        f(0, 0, FlowAction::Receive, 0),
        f(0, 0, FlowAction::Declassify, 0),
        f(1, 0, FlowAction::Declassify, 0),
        f(0, 1, FlowAction::Declassify, 0),
        f(0, 0, FlowAction::Declassify, 1),
        f(0, 0, FlowAction::Read, 1),
        f(1, 1, FlowAction::Receive, 0),
        f(0, 0, FlowAction::Contact, 1),
    ];
    let candidates = [
        f(0, 0, FlowAction::Contact, 1),
        f(1, 1, FlowAction::Contact, 1),
        f(0, 0, FlowAction::Contact, 0),
        f(0, 0, FlowAction::Read, 0),
    ];
    traces(&alphabet, 3, |events| {
        let history = History::from_events(store.clone(), events.iter().copied()).unwrap();
        for candidate in candidates {
            let answer = parsed.accepts_history(&history, &candidate).unwrap();
            assert_eq!(
                answer,
                manual.accepts_history(&history, &candidate).unwrap(),
                "{events:?}"
            );
            let mut tainted = false;
            for e in events.iter().filter(|e| {
                e.principal == candidate.principal && e.handle == candidate.handle && e.label == 0
            }) {
                match e.action {
                    FlowAction::Read | FlowAction::Receive => tainted = true,
                    FlowAction::Declassify => tainted = false,
                    FlowAction::Contact => {}
                }
            }
            let fires = candidate.action == FlowAction::Contact && candidate.label == 1;
            assert_eq!(answer, if fires { Some(tainted) } else { None });
            let denied = fires && tainted;
            assert_eq!(
                policy.decide(&history, &candidate).unwrap() != PolicyDecision::Grant,
                denied
            );
            assert_eq!(builtin.decide(&history, &candidate).is_some(), denied);
        }
        assert_eq!(history.as_slice(), events);
    });
}

fn tiny(body: &str, mode: &str) -> history_facts::Lowered<LE> {
    let source = format!(
        "language junco.facts.v1; package tiny; schema lock;
        policy x ordered {{ {mode} r on {{}} if {{ {body} }} report lock.owner; }}"
    );
    lower(
        &parse(&source, Limits::default()).unwrap(),
        &lock::LockSchema,
        Limits::default(),
    )
    .unwrap()
}

#[test]
fn empty_epsilon_all_test_complement_precedence_and_overlapping_clear_are_distinct() {
    let store = Arc::new(Store::new().unwrap());
    let cases = [
        ("true;", [true, true, true]),
        ("false;", [false, false, false]),
        ("empty_history;", [true, false, false]),
        ("exists e in history { true; };", [false, true, true]),
        (
            "complement (exists e in history { true; });",
            [true, false, false],
        ),
        (
            "since e in history { true; } unless { true; };",
            [false, true, true],
        ),
        ("true or false and false;", [true, true, true]),
        ("(true or false) and false;", [false, false, false]),
        ("", [true, true, true]),
    ];
    for (body, expected) in cases {
        for mode in ["require", "forbid"] {
            let source = tiny(body, mode);
            let mut rule =
                CompiledRule::new(store.clone(), source.obligations[0].rule.clone()).unwrap();
            let mut policy = source.compile(store.clone()).unwrap();
            for (length, accepts) in expected.into_iter().enumerate() {
                let events = vec![l(0, Action::Read, 0); length];
                let history = History::from_events(store.clone(), events).unwrap();
                let candidate = l(0, Action::Read, 0);
                assert_eq!(
                    rule.accepts_history(&history, &candidate).unwrap(),
                    Some(accepts),
                    "{body}"
                );
                let grants = if mode == "require" { accepts } else { !accepts };
                assert_eq!(
                    policy.decide(&history, &candidate).unwrap() == PolicyDecision::Grant,
                    grants
                );
            }
        }
    }
    let source = tiny(
        "exists e in history { e.action == action.edit; }; exists z in history { z.action == action.read; };",
        "require",
    );
    let mut policy = source.compile(store.clone()).unwrap();
    let history =
        History::from_events(store, [l(0, Action::Edit, 0), l(1, Action::Read, 1)]).unwrap();
    assert_eq!(
        policy.decide(&history, &l(0, Action::Release, 0)).unwrap(),
        PolicyDecision::Grant
    );
}

#[test]
fn ordered_metadata_callbacks_and_history_lifecycle_remain_paired() {
    let source = "language junco.facts.v1; package order; schema lock;
        policy a ordered { forbid first on {action: action.edit} if { true; } report lock.owner; }
        policy b ordered { forbid second on {} if { true; } report lock.stale; }";
    let lowered = lower(
        &parse(source, Limits::default()).unwrap(),
        &lock::LockSchema,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(lowered.obligations[0].metadata.name, "order.a.first");
    assert_eq!(lowered.obligations[1].metadata.ordinal, 1);
    assert_eq!(
        &source
            [lowered.obligations[1].metadata.span.start..lowered.obligations[1].metadata.span.end],
        "forbid second on {} if { true; } report lock.stale;"
    );
    let counts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let rules = lowered.into_trace_rules(|meta| {
        let name = meta.name.clone();
        let counts = counts.clone();
        move |_: &LE| {
            counts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            (name.clone(), vec!["host fix".into()])
        }
    });
    let store = Arc::new(Store::new().unwrap());
    let mut policy = TracePolicy::new(store.clone(), rules).unwrap();
    let history = History::new(store.clone()).unwrap();
    assert_eq!(
        lock_diagnostic(policy.decide(&history, &l(0, Action::Edit, 0)).unwrap()).as_deref(),
        Some("order.a.first")
    );
    assert_eq!(
        lock_diagnostic(policy.decide(&history, &l(0, Action::Read, 0)).unwrap()).as_deref(),
        Some("order.b.second")
    );
    assert_eq!(counts.load(std::sync::atomic::Ordering::Relaxed), 2);
    let foreign_store = Arc::new(Store::new().unwrap());
    let foreign = History::new(foreign_store).unwrap();
    assert!(matches!(
        policy.decide(&foreign, &l(0, Action::Edit, 0)),
        Err(junco_core::HistoryError::WrongHistoryOwner)
    ));
    assert_eq!(counts.load(std::sync::atomic::Ordering::Relaxed), 2);

    let module = parse(include_str!("../examples/flow.facts"), Limits::default()).unwrap();
    let flow_store = Arc::new(Store::new().unwrap());
    let mut flow_policy = lower(&module, &flow::FlowSchema, Limits::default())
        .unwrap()
        .compile(flow_store.clone())
        .unwrap();
    let mut history = History::new(flow_store.clone()).unwrap();
    let candidate = f(0, 0, FlowAction::Contact, 1);
    let checkpoint = history.checkpoint();
    history.push(f(0, 0, FlowAction::Read, 0)).unwrap();
    assert_ne!(
        flow_policy.decide(&history, &candidate).unwrap(),
        PolicyDecision::Grant
    );
    let fork = history.try_clone().unwrap();
    history.push(f(0, 0, FlowAction::Declassify, 0)).unwrap();
    assert_eq!(
        flow_policy.decide(&history, &candidate).unwrap(),
        PolicyDecision::Grant
    );
    assert_ne!(
        flow_policy.decide(&fork, &candidate).unwrap(),
        PolicyDecision::Grant
    );
    history.rollback(checkpoint).unwrap();
    assert_eq!(
        flow_policy.decide(&history, &candidate).unwrap(),
        PolicyDecision::Grant
    );
    let replacement = History::from_events(flow_store, [f(0, 0, FlowAction::Receive, 0)]).unwrap();
    assert_ne!(
        flow_policy.decide(&replacement, &candidate).unwrap(),
        PolicyDecision::Grant
    );
}
