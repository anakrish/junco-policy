//! Untimed native DSL/diagnostic oracles for the committed textual benchmark families.
#[path = "../benches/support/pipelines.rs"]
mod pipelines;
#[path = "../benches/smt/regexlib_subset.rs"]
mod smt;
#[path = "../benches/resharp/translate.rs"]
mod translate;

use history_pipeline::{Diagnostic, Literal, Vocabulary};
use history_semantics::{CompiledRule, PolicyDecision};
use history_store::{History, Store};
use history_syntax::{
    AtomPattern, Comparison, Component, Component3, ComponentPattern, Event, Head, RegexExpr, Rule,
    RuleMode, TestExpr,
};
use junco_policy::{
    Action, FlowAction, FlowComponent, FlowEvent, FlowPolicy, FlowRule, LockComponent, LockEvent,
    LockPolicy, RuleSet,
};
use std::sync::Arc;

type Lock = LockEvent<u32, u32>;

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
fn head() -> Head<Lock> {
    Head::new([
        ComponentPattern::variable("p"),
        ComponentPattern::Constant(LockComponent::Action(Action::Release)),
        ComponentPattern::variable("r"),
    ])
}
fn var(coordinate: usize, comparison: Comparison, name: &str) -> TestExpr<Lock> {
    atom(coordinate, comparison, ComponentPattern::variable(name))
}
fn action(value: Action, comparison: Comparison) -> TestExpr<Lock> {
    atom(
        1,
        comparison,
        ComponentPattern::Constant(LockComponent::Action(value)),
    )
}
fn equivalence<E: Event + 'static>(
    left: Rule<E>,
    right: Rule<E>,
    alphabet: &[E],
    candidates: &[E],
    max_length: u32,
) {
    let store = Arc::new(Store::new().unwrap());
    let mut left = CompiledRule::new(store.clone(), left).unwrap();
    let mut right = CompiledRule::new(store.clone(), right).unwrap();
    for length in 0..=max_length {
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
                    left.accepts_history(&history, candidate).unwrap(),
                    right.accepts_history(&history, candidate).unwrap(),
                    "{before:?}/{candidate:?}"
                );
                assert_eq!(history.as_slice(), before);
            }
        }
    }
}

#[test]
fn ordinary_validator_progress_templates_preserve_terminal_and_anywhere_meanings() {
    let edit = TestExpr::and([
        var(0, Comparison::Eq, "p"),
        action(Action::Edit, Comparison::Eq),
        var(2, Comparison::Eq, "r"),
    ]);
    let terminal = RegexExpr::concat([RegexExpr::All, RegexExpr::test(edit.clone())]);
    let prior = RegexExpr::concat([RegexExpr::All, RegexExpr::test(edit), RegexExpr::All]);
    let non_edit = TestExpr::or([
        var(2, Comparison::Neq, "r"),
        action(Action::Edit, Comparison::Neq),
    ]);
    let approval = RegexExpr::concat([
        RegexExpr::All,
        RegexExpr::test(TestExpr::and([
            var(2, Comparison::Eq, "r"),
            action(Action::Edit, Comparison::Eq),
        ])),
        RegexExpr::star(RegexExpr::test(non_edit.clone())),
        RegexExpr::test(TestExpr::and([
            var(2, Comparison::Eq, "r"),
            action(Action::Remove, Comparison::Eq),
            var(0, Comparison::Neq, "p"),
        ])),
        RegexExpr::star(RegexExpr::test(non_edit)),
    ]);
    let alphabet = [
        Lock::new(1, Action::Edit, 9),
        Lock::new(1, Action::Read, 9),
        Lock::new(2, Action::Remove, 9),
        Lock::new(2, Action::Edit, 8),
    ];
    let candidates = [
        Lock::new(1, Action::Release, 9),
        Lock::new(1, Action::Edit, 9),
    ];
    for (source, tail) in [
        (pipelines::TERMINAL_EDIT, terminal),
        (pipelines::PRIOR_EDIT, prior),
        (pipelines::APPROVAL, approval),
    ] {
        equivalence(
            pipelines::one(source, |n| n, |n| n),
            Rule::new(RuleMode::Require, head(), tail),
            &alphabet,
            &candidates,
            3,
        );
    }
    let duplicate_head = Head::new([
        ComponentPattern::variable("p"),
        ComponentPattern::Constant(LockComponent::Action(Action::Remove)),
        ComponentPattern::variable("r"),
    ]);
    let duplicate = RegexExpr::concat([
        RegexExpr::All,
        RegexExpr::test(TestExpr::and([
            action(Action::Remove, Comparison::Eq),
            var(2, Comparison::Eq, "r"),
        ])),
        RegexExpr::All,
    ]);
    equivalence(
        pipelines::one(pipelines::DUPLICATE_REMOVE, |n| n, |n| n),
        Rule::new(RuleMode::Forbid, duplicate_head, duplicate),
        &alphabet,
        &[Lock::new(1, Action::Remove, 9)],
        3,
    );
    let source = pipelines::TERMINAL_EDIT.replace("\"release\"", "\"edit\"");
    let store = Arc::new(Store::new().unwrap());
    let mut rule = CompiledRule::new(store.clone(), pipelines::one(&source, |n| n, |n| n)).unwrap();
    assert_eq!(
        rule.accepts_history(
            &History::new(store).unwrap(),
            &Lock::new(1, Action::Edit, 9)
        )
        .unwrap(),
        Some(false)
    );
}

#[test]
fn generated_depth_optional_residual_and_absent_alphabets_match_native_dsl() {
    let absent = 1 << 20;
    let leaf = |coordinate, i| {
        RegexExpr::star(RegexExpr::test(atom(
            coordinate,
            Comparison::Neq,
            ComponentPattern::Constant(if coordinate == 0 {
                LockComponent::Principal(absent + i)
            } else {
                LockComponent::Resource(absent + i)
            }),
        )))
    };
    let mut pairs = Vec::new();
    for coordinate in [0, 2] {
        let mut tail = leaf(coordinate, 0);
        for i in 1..32 {
            tail = if (i - 1) % 2 == 0 {
                RegexExpr::union([tail, leaf(coordinate, i)])
            } else {
                RegexExpr::intersect([tail, leaf(coordinate, i)])
            };
        }
        pairs.push((
            pipelines::nested(
                32,
                if coordinate == 0 {
                    "principal"
                } else {
                    "resource"
                },
                absent,
                |n| n,
                |n| n,
            ),
            Rule::new(RuleMode::Require, head(), tail),
        ));
    }
    let optional = RegexExpr::concat((0..16).map(|i| {
        RegexExpr::union([
            RegexExpr::Epsilon,
            RegexExpr::test(atom(
                2,
                Comparison::Neq,
                ComponentPattern::Constant(LockComponent::Resource(absent + i)),
            )),
        ])
    }));
    pairs.push((
        pipelines::optional(16, absent, |n| n, |n| n),
        Rule::new(RuleMode::Require, head(), optional),
    ));
    let growing = RegexExpr::concat(
        std::iter::once(RegexExpr::All)
            .chain(std::iter::once(RegexExpr::test(action(
                Action::Read,
                Comparison::Eq,
            ))))
            .chain(std::iter::repeat_n(RegexExpr::test(TestExpr::True), 5)),
    );
    pairs.push((
        pipelines::growing(4, |n| n, |n| n),
        Rule::new(RuleMode::Forbid, head(), growing),
    ));
    let absent_tail = RegexExpr::concat([
        RegexExpr::All,
        RegexExpr::test(atom(
            0,
            Comparison::Eq,
            ComponentPattern::Constant(LockComponent::Principal(absent)),
        )),
        RegexExpr::All,
    ]);
    pairs.push((
        pipelines::absent(absent, |n| n, |n| n),
        Rule::new(RuleMode::Forbid, head(), absent_tail),
    ));
    for (left, right) in pairs {
        assert_eq!(left.tail, right.tail, "generated benchmark AST shape");
        equivalence(
            left,
            right,
            &[
                Lock::new(1, Action::Read, 9),
                Lock::new(absent, Action::Edit, absent),
            ],
            &[Lock::new(1, Action::Release, 9)],
            6,
        );
    }
}

struct LockVocab;
impl Vocabulary<Lock> for LockVocab {
    fn schema(&self) -> &str {
        "Lock"
    }
    fn fields(&self) -> &[&str] {
        &["principal", "action", "resource"]
    }
    fn constant(&self, c: Component, l: &Literal) -> Option<LockComponent<u32, u32>> {
        pipelines::LockVocabulary(|n| n, |n| n).constant(c, l)
    }
    fn diagnostic(&self, name: &str) -> Option<Diagnostic> {
        ["lock_owner", "lock_stale", "lock_reader"]
            .contains(&name)
            .then(|| Diagnostic {
                message: name.into(),
                fixes: vec![],
            })
    }
}

#[test]
fn fuzz_lock_injection_preserves_native_diagnostics_fold_resets_and_errors() {
    let source = include_str!("../crates/history-pipeline/examples/lock.pipeline");
    let rules = pipelines::load(source, &LockVocab);
    let store = Arc::new(Store::new().unwrap());
    let mut text = LockPolicy::from_rules(store.clone(), rules.try_into().unwrap()).unwrap();
    let mut native = LockPolicy::new(store.clone()).unwrap();
    let alphabet = [
        Lock::new(2, Action::Read, 9),
        Lock::new(2, Action::Edit, 9),
        Lock::new(2, Action::Release, 9),
        Lock::new(1, Action::Read, 9),
        Lock::new(1, Action::Remove, 9),
        Lock::new(2, Action::Edit, 8),
    ];
    for length in 0..=3 {
        for mut word in 0..alphabet.len().pow(length) {
            let mut history = History::from_events(
                store.clone(),
                (0..length).map(|_| {
                    let event = alphabet[word % alphabet.len()];
                    word /= alphabet.len();
                    event
                }),
            )
            .unwrap();
            for a in [Action::Read, Action::Edit, Action::Release, Action::Remove] {
                let candidate = Lock::new(1, a, 9);
                assert_eq!(
                    text.decide(&history, &candidate),
                    native.decide(&history, &candidate)
                );
            }
            let clone = history.try_clone().unwrap();
            let candidate = Lock::new(1, Action::Edit, 9);
            assert_eq!(
                text.decide(&clone, &candidate),
                native.decide(&clone, &candidate)
            );
            history.truncate(0).unwrap();
            assert_eq!(
                text.decide(&history, &candidate),
                native.decide(&history, &candidate)
            );
        }
    }
    let other = History::new(Arc::new(Store::new().unwrap())).unwrap();
    assert_eq!(
        text.decide(&other, &Lock::new(1, Action::Edit, 9)),
        Err(junco_core::HistoryError::WrongHistoryOwner)
    );
}

type Flow = FlowEvent<u32, u32, u8>;
fn flow(principal: u32, handle: u32, action: FlowAction, label: u8) -> Flow {
    Flow {
        principal,
        handle,
        action,
        label,
    }
}
fn observed(decision: &PolicyDecision) -> Option<(String, Vec<String>)> {
    match decision {
        PolicyDecision::Grant => None,
        PolicyDecision::Deny {
            failed_precondition,
            allowed_fixes,
        } => Some((failed_precondition.clone(), allowed_fixes.clone())),
    }
}
struct FlowVocab;
impl Vocabulary<Flow> for FlowVocab {
    fn schema(&self) -> &str {
        "Flow"
    }
    fn fields(&self) -> &[&str] {
        &["principal", "handle", "action", "label"]
    }
    fn constant(&self, field: Component, literal: &Literal) -> Option<FlowComponent<u32, u32, u8>> {
        match (field.0, literal) {
            (0, Literal::Integer(n)) => u32::try_from(*n).ok().map(FlowComponent::Principal),
            (1, Literal::Integer(n)) => u32::try_from(*n).ok().map(FlowComponent::Handle),
            (2, Literal::String(s)) => s.parse().ok().map(FlowComponent::Action),
            (3, Literal::String(s)) => match s.as_str() {
                "untrusted" => Some(0),
                "sink" => Some(1),
                "private" => Some(2),
                "peer" => Some(3),
                _ => None,
            }
            .map(FlowComponent::Label),
            _ => None,
        }
    }
}

#[test]
fn agentdojo_audit_rules_preserve_exact_native_contact_diagnostics_and_append_behavior() {
    let rules = pipelines::load(
        include_str!("../benches/agentdojo/camel.pipeline"),
        &FlowVocab,
    );
    let text = FlowPolicy::new()
        .rule(RuleSet::new(
            rules
                .into_iter()
                .zip([(0, 1), (2, 3)])
                .map(|(rule, (taint, sink))| {
                    FlowRule::no_contact_after_read_source(rule, taint, sink)
                })
                .collect(),
        ))
        .audit();
    let native = FlowPolicy::<u32, u32, u8>::new()
        .rule(FlowRule::no_contact_after_read(0, &[1]))
        .rule(FlowRule::no_contact_after_read(2, &[3]))
        .audit();
    let alphabet = [
        flow(1, 9, FlowAction::Read, 0),
        flow(1, 9, FlowAction::Receive, 2),
        flow(1, 9, FlowAction::Declassify, 0),
        flow(2, 9, FlowAction::Declassify, 0),
        flow(1, 8, FlowAction::Declassify, 0),
        flow(1, 9, FlowAction::Declassify, 2),
    ];
    for length in 0..=3 {
        for mut word in 0..alphabet.len().pow(length) {
            let events = (0..length)
                .map(|_| {
                    let e = alphabet[word % alphabet.len()];
                    word /= alphabet.len();
                    e
                })
                .collect::<Vec<_>>();
            let store = Arc::new(Store::new().unwrap());
            let mut left = History::from_events(store.clone(), events.clone()).unwrap();
            let mut right = History::from_events(store, events).unwrap();
            let mut l = Vec::new();
            let mut r = Vec::new();
            let batch = [
                flow(1, 9, FlowAction::Contact, 1),
                flow(1, 9, FlowAction::Contact, 3),
                flow(1, 9, FlowAction::Declassify, 0),
                flow(1, 9, FlowAction::Contact, 1),
            ];
            assert_eq!(
                text.check(&mut left, &batch, |_, d| l.push(observed(d))),
                native.check(&mut right, &batch, |_, d| r.push(observed(d)))
            );
            assert_eq!(l, r);
            assert_eq!(left.as_slice(), right.as_slice());
        }
    }
}

fn byte_class(members: impl IntoIterator<Item = u8>) -> RegexExpr<translate::Symbol> {
    let mut table = [false; 256];
    for b in members {
        table[b as usize] = true;
    }
    let count = table.iter().filter(|b| **b).count();
    let atom = |b, comparison| {
        atom(
            2,
            comparison,
            ComponentPattern::Constant(Component3::C2(translate::Symbol::Byte(b))),
        )
    };
    match count {
        0 => RegexExpr::Empty,
        256 => RegexExpr::test(TestExpr::True),
        1 => RegexExpr::test(atom(
            (0..=255u8).find(|b| table[*b as usize]).unwrap(),
            Comparison::Eq,
        )),
        2..=128 => RegexExpr::test(TestExpr::or(
            (0..=255u8)
                .filter(|b| table[*b as usize])
                .map(|b| atom(b, Comparison::Eq)),
        )),
        _ => RegexExpr::test(TestExpr::and(
            (0..=255u8)
                .filter(|b| !table[*b as usize])
                .map(|b| atom(b, Comparison::Neq)),
        )),
    }
}
fn symbol_rule(tail: RegexExpr<translate::Symbol>) -> Rule<translate::Symbol> {
    Rule::new(
        RuleMode::Require,
        Head::new([
            ComponentPattern::variable("P"),
            ComponentPattern::variable("A"),
            ComponentPattern::Constant(Component3::C2(translate::Symbol::Candidate)),
        ]),
        tail,
    )
}

#[test]
fn byte_classes_keep_open_domain_singletons_and_all_complement_sequence_shapes() {
    let candidates = [translate::Symbol::Candidate];
    let alphabet = [
        translate::Symbol::Byte(0),
        translate::Symbol::Byte(b'a'),
        translate::Symbol::Byte(255),
        translate::Symbol::Candidate,
    ];
    for members in [
        vec![],
        vec![b'a'],
        vec![0, 255],
        (0..=255).filter(|b| *b != b'a').collect(),
        (0..=255).collect(),
    ] {
        let left = pipelines::language_rule(
            translate::class(members.clone()),
            &translate::Vocab,
            "Candidate | where resource == \"candidate\"",
            "require",
        );
        equivalence(
            left,
            symbol_rule(byte_class(members)),
            &alphabet,
            &candidates,
            2,
        );
    }
    let text = pipelines::Language::intersect([
        pipelines::Language::complement(translate::contains(translate::literal(b"a"))),
        pipelines::Language::union([
            pipelines::Language::epsilon(),
            pipelines::Language::star(translate::class([0, 255])),
        ]),
    ]);
    let native = RegexExpr::intersect([
        RegexExpr::complement(RegexExpr::concat([
            RegexExpr::All,
            byte_class([b'a']),
            RegexExpr::All,
        ])),
        RegexExpr::union([RegexExpr::Epsilon, RegexExpr::star(byte_class([0, 255]))]),
    ]);
    equivalence(
        pipelines::language_rule(
            text,
            &translate::Vocab,
            "Candidate | where resource == \"candidate\"",
            "require",
        ),
        symbol_rule(native),
        &alphabet,
        &candidates,
        3,
    );
}

fn native_hir(hir: &regex_syntax::hir::Hir) -> RegexExpr<translate::Symbol> {
    use regex_syntax::hir::{Class, HirKind};
    match hir.kind() {
        HirKind::Empty => RegexExpr::Epsilon,
        HirKind::Literal(lit) => RegexExpr::concat(lit.0.iter().map(|b| byte_class([*b]))),
        HirKind::Class(Class::Bytes(bytes)) => {
            byte_class(bytes.ranges().iter().flat_map(|r| r.start()..=r.end()))
        }
        HirKind::Class(Class::Unicode(_)) => panic!("byte-mode oracle"),
        HirKind::Concat(items) => RegexExpr::concat(items.iter().map(native_hir)),
        HirKind::Alternation(items) => RegexExpr::union(items.iter().map(native_hir)),
        HirKind::Capture(c) => native_hir(&c.sub),
        HirKind::Repetition(rep) => {
            let regex = native_hir(&rep.sub);
            let tail = match rep.max {
                None => Some(RegexExpr::star(regex.clone())),
                Some(hi) => {
                    let mut tail = RegexExpr::Epsilon;
                    for _ in rep.min..hi {
                        tail = RegexExpr::union([
                            RegexExpr::Epsilon,
                            RegexExpr::concat([regex.clone(), tail]),
                        ]);
                    }
                    (rep.min < hi).then_some(tail)
                }
            };
            RegexExpr::concat((0..rep.min).map(|_| regex.clone()).chain(tail))
        }
        HirKind::Look(_) => panic!("interior assertions are not supported"),
    }
}

#[test]
fn standard_byte_regex_templates_match_untimed_native_translation_including_edges() {
    use regex_syntax::hir::{Hir, HirKind, Look};
    let alphabet = [
        translate::Symbol::Byte(b'a'),
        translate::Symbol::Byte(b'A'),
        translate::Symbol::Byte(b'0'),
        translate::Symbol::Byte(b' '),
        translate::Symbol::Byte(b'\n'),
        translate::Symbol::Byte(255),
        translate::Symbol::Candidate,
    ];
    for pattern in [
        r"\s+",
        r"\d+",
        r".*",
        r"<[^>]+>",
        r"\n{3,}",
        r"\x1b\[[0-9;]*m",
        r"\$\{([^}]+)\}",
        r"\w+",
        r"\d+\.\d+\.\d+",
        r"\s{2,}",
        r"^[A-Za-z_][A-Za-z0-9_]*$",
        r"^$",
        r"\b[A-Z][a-z]+\b",
        r"[A-Za-z]{8,13}",
        r"Sherlock|Holmes|Watson|Irene|Adler",
        r"[A-Za-z0-9][A-Za-z0-9_-]{3,20}[A-Za-z0-9]",
        r"(?i)<script[^>]*>",
        r".*=.*",
    ] {
        let hir = regex_syntax::ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(pattern)
            .unwrap();
        let mut items = match hir.kind() {
            HirKind::Concat(items) => items.as_slice(),
            _ => std::slice::from_ref(&hir),
        };
        let non_word =
            || byte_class((0..=255).filter(|b: &u8| !b.is_ascii_alphanumeric() && *b != b'_'));
        let left = match items.first().map(Hir::kind) {
            Some(HirKind::Look(Look::Start)) => {
                items = &items[1..];
                RegexExpr::Epsilon
            }
            Some(HirKind::Look(Look::WordAscii)) => {
                items = &items[1..];
                RegexExpr::union([
                    RegexExpr::Epsilon,
                    RegexExpr::concat([RegexExpr::All, non_word()]),
                ])
            }
            _ => RegexExpr::All,
        };
        let right = match items.last().map(Hir::kind) {
            Some(HirKind::Look(Look::End)) => {
                items = &items[..items.len() - 1];
                RegexExpr::Epsilon
            }
            Some(HirKind::Look(Look::WordAscii)) => {
                items = &items[..items.len() - 1];
                RegexExpr::union([
                    RegexExpr::Epsilon,
                    RegexExpr::concat([non_word(), RegexExpr::All]),
                ])
            }
            _ => RegexExpr::All,
        };
        let native =
            RegexExpr::concat([left, RegexExpr::concat(items.iter().map(native_hir)), right]);
        let generated = translate::tail(translate::translate(pattern));
        equivalence(
            pipelines::language_rule(
                generated,
                &translate::Vocab,
                "Candidate | where resource == \"candidate\"",
                "require",
            ),
            symbol_rule(native),
            &alphabet,
            &[translate::Symbol::Candidate],
            3,
        );
    }
    let plain = translate::plain("a");
    equivalence(
        pipelines::language_rule(
            plain,
            &translate::Vocab,
            "Candidate | where resource == \"candidate\"",
            "require",
        ),
        symbol_rule(byte_class([b'a'])),
        &alphabet,
        &[translate::Symbol::Candidate],
        2,
    );
}

#[test]
fn smt_all_inclusion_templates_parse_and_original_nested_loop_shape_is_preserved() {
    for instance in &smt::INSTANCES {
        assert_eq!(instance.file.starts_with("unsat/"), instance.included);
        for template in [instance.left, instance.right] {
            let selector = format!(
                "Candidate | where principal == 0 and action == {} and resource == 0",
                smt::ALPHABET[0]
            );
            let rule = pipelines::language_rule(template(), &smt::Vocab, &selector, "forbid");
            rule.dispose();
        }
    }
    let mut text = pipelines::Language::<smt::Char>::epsilon();
    let test = pipelines::Language::test("any_of(action == 48, action == 49)");
    let native_test = RegexExpr::test(TestExpr::or([48, 49].map(|b| {
        atom(
            1,
            Comparison::Eq,
            ComponentPattern::Constant(Component3::C1(b)),
        )
    })));
    let mut native = RegexExpr::Epsilon;
    for _ in 1..67 {
        text = pipelines::Language::union([
            pipelines::Language::epsilon(),
            pipelines::Language::concat([test.clone(), text]),
        ]);
        native = RegexExpr::union([
            RegexExpr::Epsilon,
            RegexExpr::concat([native_test.clone(), native]),
        ]);
    }
    let text = pipelines::Language::concat([test, text]);
    let native = RegexExpr::concat([native_test, native]);
    let left = pipelines::language_rule(
        text,
        &smt::Vocab,
        "Candidate | where principal == 0 and action == 0 and resource == 0",
        "forbid",
    );
    let right = Rule::new(
        RuleMode::Forbid,
        Head::new([
            ComponentPattern::Constant(Component3::C0(())),
            ComponentPattern::Constant(Component3::C1(0)),
            ComponentPattern::Constant(Component3::C2(())),
        ]),
        native,
    );
    assert_eq!(left.tail, right.tail, "original nested optional loop AST");
    equivalence(
        left,
        right,
        &[smt::Char(48), smt::Char(49), smt::Char(0)],
        &[smt::Char(0)],
        3,
    );
}
