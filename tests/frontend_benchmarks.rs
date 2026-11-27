//! Untimed independent native DSL oracles for the actual textual benchmark loaders.
#![allow(dead_code)]

#[path = "../benches/agentdojo/bridge.rs"]
mod bridge;
#[path = "../benches/agentdojo/camel.rs"]
mod camel;
#[path = "../benches/facts/mod.rs"]
mod facts;
#[path = "../benches/progress.rs"]
mod progress;
#[path = "../benches/smt/regexlib_subset.rs"]
mod smt;
#[path = "../benches/agentdojo/tools.rs"]
mod tools;
#[path = "../benches/resharp/translate.rs"]
mod translate;
#[path = "../benches/validator.rs"]
mod validator;

use history_facts::{ErrorKind, Limits, lower, parse};
use history_semantics::CompiledRule;
use history_store::{History, Store};
use history_syntax::{
    AtomPattern, Comparison as C, Component, ComponentPattern as P, Event, Head, RegexExpr as R,
    Rule, RuleMode as M, TestExpr as T,
};
use junco_policy::{Action, LockComponent as LC, LockEvent as LE};
use std::sync::Arc;

fn atom<E: Event>(i: usize, comparison: C, pattern: P<E::Component>) -> T<E> {
    T::atom(comparison, AtomPattern::new(Component::new(i), pattern))
}
fn clean_test<E: Event>(test: T<E>) -> T<E> {
    match test {
        T::And(xs) | T::Or(xs) if xs.len() == 1 => clean_test(xs.into_iter().next().unwrap()),
        T::And(xs) => T::And(xs.into_iter().map(clean_test).collect()),
        T::Or(xs) => T::Or(xs.into_iter().map(clean_test).collect()),
        x => x,
    }
}
fn clean<E: Event>(regex: R<E>) -> R<E> {
    match regex {
        R::Intersect(xs) if xs.len() == 1 => clean(xs.into_iter().next().unwrap()),
        R::Test(t) => R::Test(clean_test(t)),
        R::Concat(xs) => R::Concat(xs.into_iter().map(clean).collect()),
        R::Union(xs) => R::Union(xs.into_iter().map(clean).collect()),
        R::Intersect(xs) => R::Intersect(xs.into_iter().map(clean).collect()),
        R::Star(x) => R::star(clean(*x)),
        R::Not(x) => R::complement(clean(*x)),
        x => x,
    }
}
fn differential<E: Event>(parsed: Rule<E>, native: Rule<E>, alphabet: &[E], candidates: &[E]) {
    let store = Arc::new(Store::new().unwrap());
    let mut a = CompiledRule::new(store.clone(), parsed).unwrap();
    let mut b = CompiledRule::new(store.clone(), native).unwrap();
    let mut histories = vec![vec![]];
    for _ in 0..3 {
        let mut next = Vec::new();
        for history in &histories {
            for &event in alphabet {
                let mut extended = history.clone();
                extended.push(event);
                next.push(extended);
            }
        }
        histories.extend(next);
    }
    for events in histories {
        let history = History::from_events(store.clone(), events.iter().copied()).unwrap();
        for candidate in candidates {
            assert_eq!(
                a.accepts_history(&history, candidate).unwrap(),
                b.accepts_history(&history, candidate).unwrap(),
                "{events:?} {candidate:?}"
            );
        }
        assert_eq!(history.as_slice(), events);
    }
}

type V = LE<validator::Actor, validator::Path>;
fn v(action: Action, p: u32, r: u32) -> V {
    LE::new(validator::Actor(p), action, validator::Path(r))
}
fn vhead(action: Action) -> Head<V> {
    Head::new([
        P::variable("actor"),
        P::constant(LC::Action(action)),
        P::variable("target"),
    ])
}
fn va(i: usize, cmp: C, pattern: P<LC<validator::Actor, validator::Path>>) -> T<V> {
    atom(i, cmp, pattern)
}
fn vaction(action: Action) -> T<V> {
    va(1, C::Eq, P::constant(LC::Action(action)))
}

#[test]
fn validator_terminal_prior_duplicate_and_synthetic_families() {
    let edit = T::and([
        va(0, C::Eq, P::variable("actor")),
        vaction(Action::Edit),
        va(2, C::Eq, P::variable("target")),
    ]);
    let native = Rule::new(
        M::Require,
        vhead(Action::Release),
        R::concat([R::All, R::Test(edit)]),
    );
    differential(
        validator::prior_edit_rule(7),
        native,
        &[
            v(Action::Edit, 0, 0),
            v(Action::Read, 0, 0),
            v(Action::Edit, 1, 1),
        ],
        &[v(Action::Release, 0, 0), v(Action::Edit, 0, 0)],
    );
    let removal = T::and([vaction(Action::Remove), va(2, C::Eq, P::variable("target"))]);
    differential(
        validator::duplicate_remove_rule(),
        Rule::new(
            M::Forbid,
            vhead(Action::Remove),
            R::concat([R::All, R::Test(removal), R::All]),
        ),
        &[
            v(Action::Remove, 0, 0),
            v(Action::Read, 0, 0),
            v(Action::Remove, 0, 1),
        ],
        &[v(Action::Remove, 0, 0), v(Action::Read, 0, 0)],
    );

    for coordinate in [0, 2] {
        let leaf = |index: u32| {
            R::star(R::Test(va(
                coordinate,
                C::Neq,
                P::constant(if coordinate == 0 {
                    LC::Principal(validator::Actor((1 << 20) + index))
                } else {
                    LC::Resource(validator::Path((1 << 20) + index))
                }),
            )))
        };
        let mut native = leaf(0);
        for index in 1..32 {
            native = if index % 2 == 1 {
                R::union([native, leaf(index)])
            } else {
                R::intersect([native, leaf(index)])
            };
        }
        let parsed = if coordinate == 0 {
            validator::deeply_nested_allow_all_rule(32)
        } else {
            validator::deeply_nested_resource_allow_all_rule(32)
        };
        assert_eq!(clean(parsed.tail.clone()), native);
        differential(
            parsed,
            Rule::new(M::Require, vhead(Action::Release), native),
            &[v(Action::Read, 0, 0), v(Action::Edit, 1 << 20, 1 << 20)],
            &[v(Action::Release, 0, 0)],
        );
    }
    let optional = R::concat((0..16).map(|i| {
        R::union([
            R::Epsilon,
            R::Test(va(
                2,
                C::Neq,
                P::constant(LC::Resource(validator::Path((1 << 20) + i))),
            )),
        ])
    }));
    let parsed = validator::advancing_optional_rule(16);
    assert_eq!(clean(parsed.tail.clone()), optional);
    differential(
        parsed,
        Rule::new(M::Require, vhead(Action::Release), optional),
        &[v(Action::Read, 0, 0), v(Action::Read, 0, 1 << 20)],
        &[v(Action::Release, 0, 0)],
    );
    for window in [4, 8, 12, 16, 32, 64] {
        let native = R::concat(
            std::iter::once(R::All)
                .chain(std::iter::once(R::Test(vaction(Action::Read))))
                .chain(std::iter::repeat_n(R::Test(T::True), window + 1)),
        );
        let parsed = validator::growing_residual_rule(window);
        assert_eq!(clean(parsed.tail), native);
    }
    for index in [0, 15, 63, 255, 1023] {
        let native = R::concat([
            R::All,
            R::Test(va(
                0,
                C::Eq,
                P::constant(LC::Principal(validator::Actor((1 << 20) + index))),
            )),
            R::All,
        ]);
        differential(
            validator::absent_witness_rule(index as usize),
            Rule::new(M::Forbid, vhead(Action::Release), native),
            &[v(Action::Read, 0, 0), v(Action::Read, (1 << 20) + index, 0)],
            &[v(Action::Release, 0, 0)],
        );
    }
    let store = Arc::new(Store::new().unwrap());
    let mut rule = CompiledRule::new(store.clone(), validator::prior_edit_rule(0)).unwrap();
    let history =
        History::from_events(store, [v(Action::Edit, 0, 0), v(Action::Read, 0, 0)]).unwrap();
    assert_eq!(
        rule.accepts_history(&history, &v(Action::Release, 0, 0))
            .unwrap(),
        Some(false)
    );
}

#[test]
fn progress_prior_and_release_approval_native_oracles() {
    type G = LE<progress::Actor, progress::Path>;
    let head = || {
        Head::<G>::new([
            P::variable("actor"),
            P::constant(LC::Action(Action::Release)),
            P::variable("resource"),
        ])
    };
    let var = |i, cmp| {
        atom::<G>(
            i,
            cmp,
            P::variable(if i == 0 { "actor" } else { "resource" }),
        )
    };
    let action = |a, cmp| atom::<G>(1, cmp, P::constant(LC::Action(a)));
    let prior = R::concat([
        R::All,
        R::Test(T::and([
            var(0, C::Eq),
            action(Action::Edit, C::Eq),
            var(2, C::Eq),
        ])),
        R::All,
    ]);
    let non_edit = T::or([var(2, C::Neq), action(Action::Edit, C::Neq)]);
    let approval = R::concat([
        R::All,
        R::Test(T::and([var(2, C::Eq), action(Action::Edit, C::Eq)])),
        R::star(R::Test(non_edit.clone())),
        R::Test(T::and([
            var(2, C::Eq),
            action(Action::Remove, C::Eq),
            var(0, C::Neq),
        ])),
        R::star(R::Test(non_edit)),
    ]);
    let event = |a, p, r| LE::new(progress::Actor(p), a, progress::Path(r));
    let alphabet = [
        event(Action::Edit, 0, 0),
        event(Action::Remove, 1, 0),
        event(Action::Remove, 0, 0),
        event(Action::Edit, 1, 1),
        event(Action::Read, 0, 0),
    ];
    for (parsed, tail) in [
        (progress::prior_edit_rule(), prior),
        (progress::release_approval_rule(), approval),
    ] {
        differential(
            parsed,
            Rule::new(M::Require, head(), tail),
            &alphabet,
            &[
                event(Action::Release, 0, 0),
                event(Action::Release, 1, 0),
                event(Action::Read, 0, 0),
            ],
        );
    }
}

#[test]
fn locks_native_diagnostics_and_reset_folds_are_preserved() {
    let schema = facts::LockSchema(|n| n as u8, |n| n as u8);
    let store = Arc::new(Store::new().unwrap());
    let mut text =
        junco_policy::LockPolicy::from_sources(store.clone(), facts::lock_sources(&schema))
            .unwrap();
    let mut native = junco_policy::LockPolicy::new(store.clone()).unwrap();
    let event = |p, a, r| LE::new(p, a, r);
    let alphabet = [
        event(1, Action::Edit, 0),
        event(1, Action::Release, 0),
        event(1, Action::Remove, 0),
        event(0, Action::Read, 0),
        event(1, Action::Read, 0),
        event(1, Action::Remove, 1),
    ];
    for &a in &alphabet {
        for &b in &alphabet {
            for &c in &alphabet {
                let history = History::from_events(store.clone(), [a, b, c]).unwrap();
                for action in [Action::Read, Action::Edit, Action::Release, Action::Remove] {
                    let candidate = event(0, action, 0);
                    assert_eq!(
                        text.decide(&history, &candidate).unwrap(),
                        native.decide(&history, &candidate).unwrap()
                    );
                }
                assert_eq!(history.as_slice(), &[a, b, c]);
            }
        }
    }
    let empty = History::new(store.clone()).unwrap();
    assert_eq!(
        text.decide(&empty, &event(0, Action::Release, 0)).unwrap(),
        native
            .decide(&empty, &event(0, Action::Release, 0))
            .unwrap()
    );
    let mut growing = History::new(store).unwrap();
    let checkpoint = growing.checkpoint();
    growing.push(event(1, Action::Edit, 0)).unwrap();
    let fork = growing.try_clone().unwrap();
    growing.push(event(1, Action::Remove, 0)).unwrap();
    for history in [&growing, &fork] {
        assert_eq!(
            text.decide(history, &event(0, Action::Edit, 0)).unwrap(),
            native.decide(history, &event(0, Action::Edit, 0)).unwrap()
        );
    }
    growing.rollback(checkpoint).unwrap();
    assert_eq!(
        text.decide(&growing, &event(0, Action::Edit, 0)).unwrap(),
        native.decide(&growing, &event(0, Action::Edit, 0)).unwrap()
    );
}

#[test]
fn camel_two_label_families_preserve_native_diagnostics_audit_and_resets() {
    use camel::{Agent, Class, Handle};
    use junco_policy::{FlowAction as A, FlowEvent, FlowPolicy, FlowRule};
    let text = camel::camel_policy();
    let native = FlowPolicy::new()
        .rule(FlowRule::no_contact_after_read(
            Class::Untrusted,
            &[Class::Sink],
        ))
        .rule(FlowRule::no_contact_after_read(
            Class::Private,
            &[Class::Peer],
        ))
        .audit();
    let event = |p, v, action, label| FlowEvent {
        principal: p,
        handle: Handle(v),
        action,
        label,
    };
    for (source, sink) in [
        (Class::Untrusted, Class::Sink),
        (Class::Private, Class::Peer),
    ] {
        let candidate = event(Agent::P, 0, A::Contact, sink);
        let reset = [
            event(Agent::P, 0, A::Declassify, source),
            event(Agent::Q, 0, A::Declassify, source),
            event(Agent::P, 1, A::Declassify, source),
            event(Agent::P, 0, A::Declassify, Class::Trusted),
        ];
        for clear in reset {
            let store = Arc::new(Store::new().unwrap());
            let mut a = History::from_events(
                store.clone(),
                [event(Agent::P, 0, A::Receive, source), clear],
            )
            .unwrap();
            let mut b = a.try_clone().unwrap();
            assert_eq!(text.decide(&a, &candidate), native.decide(&a, &candidate));
            let mut observed_a = None;
            let mut observed_b = None;
            assert_eq!(
                text.check(&mut a, &[candidate], |_, d| observed_a =
                    Some(format!("{d:?}"))),
                native.check(&mut b, &[candidate], |_, d| observed_b =
                    Some(format!("{d:?}")))
            );
            assert_eq!(observed_a, observed_b);
            assert_eq!(a.as_slice(), b.as_slice());
            assert_eq!(a.as_slice().last(), Some(&candidate));
        }
    }
}

fn native_byte_class(members: &[u8]) -> R<translate::Symbol> {
    use history_syntax::Component3;
    let mut table = [false; 256];
    for &b in members {
        table[b as usize] = true;
    }
    let count = table.iter().filter(|&&b| b).count();
    let comparison = if count <= 128 { C::Eq } else { C::Neq };
    let atoms: Vec<_> = (0..=255u8)
        .filter(|&b| table[b as usize] == (count <= 128))
        .map(|b| {
            atom(
                2,
                comparison,
                P::constant(Component3::C2(translate::Symbol::Byte(b))),
            )
        })
        .collect();
    match count {
        0 => R::Empty,
        256 => R::Test(T::True),
        1 => R::Test(atoms.into_iter().next().unwrap()),
        2..=128 => R::Test(T::Or(atoms)),
        _ => R::Test(T::And(atoms)),
    }
}

#[test]
fn byte_translation_preserves_open_domain_classes_and_bounded_repeat_shapes() {
    use translate::{Symbol, SymbolSchema};
    let candidate = Symbol::Candidate;
    for members in [vec![], vec![b'a'], (0..=128).collect(), (0..=255).collect()] {
        let source = facts::rule(
            translate::class(members.clone()),
            "require",
            "resource: resource.candidate",
            &SymbolSchema,
        );
        let native = Rule::new(M::Require, source.head.clone(), native_byte_class(&members));
        differential(
            source,
            native,
            &[Symbol::Byte(b'a'), Symbol::Byte(255), candidate],
            &[candidate],
        );
    }
    let sources = [
        ("a{1,67}", b"a".as_slice()),
        ("^$", b"".as_slice()),
        ("ab|cd", b"cd".as_slice()),
        (r"\b[A-Z][a-z]+\b", b" Xy ".as_slice()),
        ("[^a]", b"\xff".as_slice()),
        ("a{2,3}", b"aaa".as_slice()),
        ("^a$", b"aa".as_slice()),
    ];
    for (pattern, sample) in sources {
        let source = facts::rule(
            translate::tail(translate::translate(pattern)),
            "require",
            "resource: resource.candidate",
            &SymbolSchema,
        );
        let store = Arc::new(Store::new().unwrap());
        let mut rule = CompiledRule::new(store.clone(), source).unwrap();
        let history =
            History::from_events(store, sample.iter().copied().map(Symbol::Byte)).unwrap();
        let regex = resharp::Regex::with_options(
            pattern,
            resharp::RegexOptions::default()
                .unicode(resharp::UnicodeMode::Ascii)
                .multiline(false),
        )
        .unwrap();
        assert_eq!(
            rule.accepts_history(&history, &candidate).unwrap(),
            Some(regex.is_match(sample).unwrap())
        );
    }
    let text = translate::plain("a{1,67}");
    let source = facts::rule(
        text,
        "require",
        "resource: resource.candidate",
        &SymbolSchema,
    );
    let a = R::concat([native_byte_class(b"a")]);
    let mut optional = R::Epsilon;
    for _ in 1..67 {
        optional = R::union([R::Epsilon, R::concat([a.clone(), optional])]);
    }
    assert_eq!(clean(source.tail), R::concat([R::concat([a, optional])]));
}

fn smt_native(index: usize) -> R<smt::Char> {
    let second = index >= 10;
    let c = |n: usize| {
        let n = if second {
            match n {
                0 => 23,
                8 => 24,
                13 => 25,
                14 => 26,
                15 => 27,
                18 => 29,
                19 => 32,
                22 => 33,
                _ => n,
            }
        } else {
            n
        };
        R::Test(T::Or(
            smt::CLASSES[n]
                .iter()
                .map(|&b| atom(1, C::Eq, P::constant(history_syntax::Component3::C1(b))))
                .collect(),
        ))
    };
    fn opt<E: Event>(r: R<E>) -> R<E> {
        R::union([R::Epsilon, r])
    }
    fn plus<E: Event>(r: R<E>) -> R<E> {
        R::concat([r.clone(), R::star(r)])
    }
    fn repeat<E: Event>(r: R<E>, lo: usize, hi: usize) -> R<E> {
        let mut tail = R::Epsilon;
        for _ in lo..hi {
            tail = opt(R::concat([r.clone(), tail]));
        }
        R::concat((0..lo).map(|_| r.clone()).chain((lo < hi).then_some(tail)))
    }
    let email = || {
        R::concat([
            plus(c(0)),
            R::star(R::concat([c(1), plus(c(0))])),
            c(2),
            plus(c(0)),
            R::star(R::concat([c(3), plus(c(0))])),
            c(4),
            plus(c(0)),
            R::star(R::concat([c(3), plus(c(0))])),
        ])
    };
    match index % 10 {
        0 => {
            // The original formula has one flat concat, not an extra nested email concat.
            let R::Concat(mut prefix) = email() else {
                unreachable!()
            };
            let R::Concat(mut suffix) = email() else {
                unreachable!()
            };
            suffix.insert(0, R::star(c(6)));
            suffix.insert(0, c(5));
            prefix.push(R::star(R::concat(suffix)));
            R::concat(prefix)
        }
        1 => R::concat([
            opt(c(7)),
            R::union([
                R::concat([
                    repeat(c(8), 1, 3),
                    opt(c(9)),
                    R::star(R::concat([repeat(c(8), 3, 3), opt(c(9))])),
                    repeat(c(8), 3, 3),
                    opt(R::concat([c(4), repeat(c(8), 0, 2)])),
                ]),
                R::concat([
                    repeat(c(8), 1, 3),
                    opt(R::concat([c(4), repeat(c(8), 0, 2)])),
                ]),
                R::concat([c(4), opt(repeat(c(8), 1, 2))]),
            ]),
        ]),
        2 => R::concat([
            opt(R::union([
                repeat(c(10), 2, 2),
                R::concat([
                    repeat(c(11), 2, 2),
                    c(12),
                    repeat(c(8), 2, 2),
                    c(12),
                    repeat(c(10), 1, 2),
                ]),
                R::concat([repeat(c(11), 1, 2), c(12), repeat(c(8), 1, 4)]),
            ])),
            opt(R::union([
                repeat(c(10), 3, 3),
                R::concat([repeat(c(11), 3, 3), c(12), repeat(c(8), 1, 4)]),
            ])),
        ]),
        3 => R::concat([
            c(13),
            R::star(R::concat([opt(c(3)), plus(c(13))])),
            c(2),
            plus(c(13)),
            R::star(R::concat([opt(c(3)), plus(c(13))])),
            c(14),
            plus(c(14)),
        ]),
        4 => R::concat([
            plus(c(15)),
            c(2),
            plus(R::concat([plus(c(15)), c(4)])),
            plus(c(15)),
        ]),
        5 => {
            let digits = if second {
                R::Test(T::Or(
                    smt::CLASSES[28]
                        .iter()
                        .map(|&b| atom(1, C::Eq, P::constant(history_syntax::Component3::C1(b))))
                        .collect(),
                ))
            } else {
                c(8)
            };
            R::concat([
                opt(c(16)),
                R::union([
                    R::concat([R::star(digits.clone()), opt(c(4)), plus(digits.clone())]),
                    R::concat([plus(digits.clone()), opt(c(4)), R::star(digits.clone())]),
                ]),
                opt(R::concat([c(17), opt(c(16)), plus(digits)])),
            ])
        }
        6 => {
            let named = |n: usize| {
                R::Test(T::Or(
                    smt::CLASSES[n]
                        .iter()
                        .map(|&b| atom(1, C::Eq, P::constant(history_syntax::Component3::C1(b))))
                        .collect(),
                ))
            };
            let local_word = if second { named(30) } else { c(15) };
            let letters = if second { named(31) } else { c(13) };
            R::concat([
                plus(c(18)),
                c(2),
                R::union([
                    repeat(local_word.clone(), 1, 67),
                    R::concat([plus(local_word.clone()), c(4), repeat(local_word, 1, 67)]),
                ]),
                c(4),
                repeat(letters, 2, 4),
                opt(R::concat([c(4), repeat(c(19), 2, 2)])),
            ])
        }
        7 => {
            let alnum = R::Test(T::Or(
                smt::CLASSES[13]
                    .iter()
                    .map(|&b| atom(1, C::Eq, P::constant(history_syntax::Component3::C1(b))))
                    .collect(),
            ));
            R::concat([
                R::star(R::union(
                    [12, 20, 4, 21].map(|n| R::concat([plus(alnum.clone()), plus(c(n))])),
                )),
                plus(alnum),
                c(2),
                R::star(R::union([
                    R::concat([plus(c(0)), plus(c(20))]),
                    R::concat([plus(c(0)), c(4)]),
                ])),
                repeat(c(0), 1, 63),
                c(4),
                repeat(
                    R::Test(T::Or(
                        smt::CLASSES[14]
                            .iter()
                            .map(|&b| {
                                atom(1, C::Eq, P::constant(history_syntax::Component3::C1(b)))
                            })
                            .collect(),
                    )),
                    2,
                    6,
                ),
            ])
        }
        8 => {
            let mail = || {
                R::concat([
                    plus(c(22)),
                    c(2),
                    plus(c(22)),
                    c(4),
                    repeat(repeat(c(14), 2, 5), 1, 25),
                ])
            };
            R::concat([plus(mail()), R::star(plus(mail()))])
        }
        9 => {
            let R::Concat(mut parts) = email() else {
                unreachable!()
            };
            parts.extend([R::star(c(6)), opt(c(9)), R::star(c(6))]);
            plus(R::concat(parts))
        }
        _ => unreachable!(),
    }
}

#[test]
fn every_smt_formula_keeps_exact_original_algebra_and_declared_alphabet() {
    let mut seen = Vec::new();
    for instance in &smt::INSTANCES {
        for (factory, index) in [
            (
                instance.left,
                instance
                    .file
                    .split('/')
                    .nth(1)
                    .unwrap()
                    .split('_')
                    .nth(1)
                    .unwrap()
                    .parse::<usize>()
                    .unwrap()
                    + if instance.file.starts_with("unsat/") {
                        10
                    } else {
                        0
                    },
            ),
            (
                instance.right,
                instance
                    .file
                    .split('/')
                    .nth(1)
                    .unwrap()
                    .split('_')
                    .nth(2)
                    .unwrap()
                    .trim_end_matches(".smt2")
                    .parse::<usize>()
                    .unwrap(),
            ),
        ] {
            if seen.contains(&index) {
                continue;
            }
            seen.push(index);
            let parsed = smt::source(factory());
            let native = smt_native(index);
            assert_eq!(
                clean(parsed.tail.clone()),
                clean(native.clone()),
                "formula {index}"
            );
            differential(
                parsed.clone(),
                Rule::new(M::Forbid, parsed.head.clone(), native),
                &[smt::Char(0), smt::Char(b'a'), smt::Char(b'@')],
                &[smt::Char(smt::ALPHABET[0]), smt::Char(255)],
            );
        }
    }
    assert_eq!(seen.len(), 20);
    assert_eq!(smt::INSTANCES.len(), 100);
}

#[test]
fn explicit_algebra_empty_singleton_complement_and_depth_limits() {
    let schema = facts::LockSchema(|n| n as u8, |n| n as u8);
    let head = "action: action.release";
    for (text, native) in [
        (facts::Algebra::all(), R::All),
        (facts::Algebra::empty(), R::Empty),
        (facts::Algebra::epsilon(), R::Epsilon),
        (facts::Algebra::event("true;"), R::Test(T::True)),
        (
            facts::Algebra::complement(facts::Algebra::event("true;")),
            R::complement(R::Test(T::True)),
        ),
        (facts::Algebra::concat([]), R::Concat(vec![])),
        (facts::Algebra::union([]), R::Union(vec![])),
        (facts::Algebra::intersect([]), R::Intersect(vec![])),
    ] {
        let source = facts::rule(text, "require", head, &schema);
        differential(
            source.clone(),
            Rule::new(M::Require, source.head, native),
            &[LE::new(0, Action::Read, 0)],
            &[LE::new(0, Action::Release, 0)],
        );
    }
    let make = |ops: &str| {
        format!("language junco.facts.v1; package test; schema lock;
        policy p ordered {{ require r on {{}} if {{ algebra {{ {ops} }}; }} report benchmark.rule; }}")
    };
    for ops in [
        "star;",
        "all; all;",
        "all; concat count.2;",
        "concat count.999999999999999999999999;",
        "all; arbitrary;",
        "event e { e.resource == p; };",
    ] {
        let source = make(ops);
        let result =
            parse(&source, Limits::default()).and_then(|m| lower(&m, &schema, Limits::default()));
        assert!(result.is_err(), "{ops}");
    }
    let exact = make(&format!("all;{}", "star;".repeat(255)));
    let module = parse(&exact, Limits::default()).unwrap();
    let lowered = lower(&module, &schema, Limits::default()).unwrap();
    for o in lowered.obligations {
        o.rule.dispose();
    }
    let over = make(&format!("all;{}", "star;".repeat(256)));
    let module = parse(&over, Limits::default()).unwrap();
    assert_eq!(
        lower(&module, &schema, Limits::default()).unwrap_err().kind,
        ErrorKind::Limit
    );
}
