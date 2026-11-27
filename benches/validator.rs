//! Criterion benchmarks for compilation, history evaluation, full scans, denial, and rollback.
//!
//! Run the suite from this package with `cargo bench --bench validator`. Pass a Criterion filter,
//! for example `cargo bench --bench validator -- history_scan`, to run one group.

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use history_semantics::{Decision, Validator};
use history_store::Store;
use history_syntax::{
    AtomPattern, Comparison, Component, ComponentPattern, Head, RegexExpr, Rule, RuleMode, TestExpr,
};
use junco_core::Request;
use junco_policy::{Action, LockComponent, LockEvent};
use std::sync::Arc;
#[path = "text/mod.rs"]
#[allow(dead_code)]
mod text;

/// Benchmark principal identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Actor(u32);

/// Benchmark resource identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Path(u32);

const ALICE: Actor = Actor(0);
const CANDIDATE: Actor = Actor(1);
const HISTORY: Actor = Actor(2);
/// First id of principals and resources named only by rule constants; no benchmark event carries
/// one.
const ABSENT_IDS: u32 = 1 << 20;
/// First id of the high-cardinality history's unique principals and resources.
const UNIQUE_IDS: u32 = 1 << 24;

const ROOT: Path = Path(0);
const SRC_A: Path = Path(1);
const A: Path = Path(2);
const TARGET: Path = Path(3);
const EVENT: Path = Path(4);

fn request(actor: Actor, action: Action, path: Path) -> Request<LockEvent<Actor, Path>, ()> {
    Request::new(LockEvent::new(actor, action, path), ())
}

fn native_prior_edit_rule(suffix: usize) -> Rule<LockEvent<Actor, Path>> {
    let actor = format!("actor-{suffix}");
    let target = format!("target-{suffix}");
    let principal = TestExpr::atom(
        Comparison::Eq,
        AtomPattern::new(Component(0), ComponentPattern::variable(actor.clone())),
    );
    let action = TestExpr::atom(
        Comparison::Eq,
        AtomPattern::new(
            Component(1),
            ComponentPattern::constant(LockComponent::Action(Action::Edit)),
        ),
    );
    let resource = TestExpr::atom(
        Comparison::Eq,
        AtomPattern::new(Component(2), ComponentPattern::variable(target.clone())),
    );
    Rule::new(
        RuleMode::Require,
        Head::new([
            ComponentPattern::variable(actor),
            ComponentPattern::constant(LockComponent::Action(Action::Release)),
            ComponentPattern::variable(target),
        ]),
        RegexExpr::concat([
            RegexExpr::all(),
            RegexExpr::test(TestExpr::and([principal, action, resource])),
        ]),
    )
}

fn native_duplicate_remove_rule() -> Rule<LockEvent<Actor, Path>> {
    let matching_remove = RegexExpr::test(TestExpr::and([
        TestExpr::atom(
            Comparison::Eq,
            AtomPattern::new(
                Component(1),
                ComponentPattern::constant(LockComponent::Action(Action::Remove)),
            ),
        ),
        TestExpr::atom(
            Comparison::Eq,
            AtomPattern::new(Component(2), ComponentPattern::variable("target")),
        ),
    ]));
    Rule::new(
        RuleMode::Forbid,
        Head::new([
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(LockComponent::Action(Action::Remove)),
            ComponentPattern::variable("target"),
        ]),
        RegexExpr::concat([RegexExpr::all(), matching_remove, RegexExpr::all()]),
    )
}

fn every_resource_leaf(index: usize) -> RegexExpr<LockEvent<Actor, Path>> {
    RegexExpr::star(RegexExpr::test(TestExpr::atom(
        Comparison::Neq,
        AtomPattern::new(
            Component(2),
            ComponentPattern::constant(LockComponent::Resource(Path(ABSENT_IDS + index as u32))),
        ),
    )))
}

fn native_deeply_nested_resource_allow_all_rule(depth: usize) -> Rule<LockEvent<Actor, Path>> {
    assert!(depth > 0, "regex depth must be positive");
    let mut leaves = (0..depth).map(every_resource_leaf);
    let mut tail = leaves.next().expect("positive depth has one leaf");
    for (index, leaf) in leaves.enumerate() {
        tail = if index % 2 == 0 {
            RegexExpr::union([tail, leaf])
        } else {
            RegexExpr::intersect([tail, leaf])
        };
    }
    Rule::new(
        RuleMode::Require,
        Head::new([
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(LockComponent::Action(Action::Release)),
            ComponentPattern::variable("target"),
        ]),
        tail,
    )
}

fn unique_read(index: usize) -> Request<LockEvent<Actor, Path>, ()> {
    let id = UNIQUE_IDS + u32::try_from(index).expect("benchmark index fits u32");
    request(Actor(id), Action::Read, Path(id))
}

// Each distinct star accepts every benchmark event and is stable under differentiation.
fn every_event_leaf(index: usize) -> RegexExpr<LockEvent<Actor, Path>> {
    RegexExpr::star(RegexExpr::test(TestExpr::atom(
        Comparison::Neq,
        AtomPattern::new(
            Component(0),
            ComponentPattern::constant(LockComponent::Principal(Actor(ABSENT_IDS + index as u32))),
        ),
    )))
}

fn native_deeply_nested_allow_all_rule(depth: usize) -> Rule<LockEvent<Actor, Path>> {
    assert!(depth > 0, "regex depth must be positive");
    let mut leaves = (0..depth).map(every_event_leaf);
    let mut tail = leaves.next().expect("positive depth has one leaf");
    // Alternating operators retain binary nesting because canonicalization only flattens like kinds.
    for (index, leaf) in leaves.enumerate() {
        tail = if index % 2 == 0 {
            RegexExpr::union([tail, leaf])
        } else {
            RegexExpr::intersect([tail, leaf])
        };
    }

    Rule::new(
        RuleMode::Require,
        Head::new([
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(LockComponent::Action(Action::Release)),
            ComponentPattern::variable("target"),
        ]),
        tail,
    )
}

fn native_advancing_optional_rule(steps: usize) -> Rule<LockEvent<Actor, Path>> {
    let factors = (0..steps).map(|index| {
        RegexExpr::union([
            RegexExpr::epsilon(),
            RegexExpr::test(TestExpr::atom(
                Comparison::Neq,
                AtomPattern::new(
                    Component(2),
                    ComponentPattern::constant(LockComponent::Resource(Path(
                        ABSENT_IDS + index as u32,
                    ))),
                ),
            )),
        ])
    });
    Rule::new(
        RuleMode::Require,
        Head::new([
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(LockComponent::Action(Action::Release)),
            ComponentPattern::variable("target"),
        ]),
        RegexExpr::concat(factors),
    )
}

/// Language whose residual DAG gains one suffix alternative after each matching event.
///
/// `Σ* · Read · Σ^(window + 1)` recognizes histories whose `(window + 2)`th event from the end is a
/// read. A shorter all-read history keeps adding candidate suffixes without reaching a terminal
/// residual. The full DFA has exponentially many states even though this measured path grows
/// linearly.
fn native_growing_residual_rule(window: usize) -> Rule<LockEvent<Actor, Path>> {
    assert!(window > 0, "residual-growth window must be positive");
    let any_event = RegexExpr::test(TestExpr::true_test());
    let read = RegexExpr::test(TestExpr::atom(
        Comparison::Eq,
        AtomPattern::new(
            Component(1),
            ComponentPattern::constant(LockComponent::Action(Action::Read)),
        ),
    ));
    let factors = std::iter::once(RegexExpr::all())
        .chain(std::iter::once(read))
        .chain(std::iter::repeat_n(any_event, window + 1));
    Rule::new(
        RuleMode::Forbid,
        Head::new([
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(LockComponent::Action(Action::Release)),
            ComponentPattern::variable("target"),
        ]),
        RegexExpr::concat(factors),
    )
}

/// One unique absent-witness rule that forces a complete nonterminal history scan.
fn native_absent_witness_rule(index: usize) -> Rule<LockEvent<Actor, Path>> {
    let absent = RegexExpr::test(TestExpr::atom(
        Comparison::Eq,
        AtomPattern::new(
            Component(0),
            ComponentPattern::constant(LockComponent::Principal(Actor(ABSENT_IDS + index as u32))),
        ),
    ));
    Rule::new(
        RuleMode::Forbid,
        Head::new([
            ComponentPattern::variable("actor"),
            ComponentPattern::constant(LockComponent::Action(Action::Release)),
            ComponentPattern::variable("target"),
        ]),
        RegexExpr::concat([RegexExpr::all(), absent, RegexExpr::all()]),
    )
}

fn authored(name: &str, mode: &str, action: &str, tail: &str) -> Rule<LockEvent<Actor, Path>> {
    text::lock_rule(&text::lock_document(name, mode, action, tail), Actor, Path)
}

fn prior_edit_rule(suffix: usize) -> Rule<LockEvent<Actor, Path>> {
    // Terminal witness: unlike the README example, no trailing `all`.
    authored(
        &format!("prior_edit_{suffix}"),
        "require",
        "release",
        "all >> event { principal == $actor and action == action.edit and resource == $target }",
    )
}
fn duplicate_remove_rule() -> Rule<LockEvent<Actor, Path>> {
    authored(
        "duplicate_remove",
        "forbid",
        "remove",
        "all >> event { action == action.remove and resource == $target } >> all",
    )
}
fn nested(depth: usize, coordinate: &str) -> Rule<LockEvent<Actor, Path>> {
    assert!(depth > 0);
    let leaf = |index| format!("event {{ {coordinate} != {} }}*", ABSENT_IDS + index as u32);
    let mut tail = leaf(0);
    for index in 1..depth {
        let op = if (index - 1) % 2 == 0 { "|" } else { "&" };
        tail = format!("({tail} {op} {})", leaf(index));
    }
    authored("nested", "require", "release", &tail)
}
fn deeply_nested_allow_all_rule(depth: usize) -> Rule<LockEvent<Actor, Path>> {
    nested(depth, "principal")
}
fn deeply_nested_resource_allow_all_rule(depth: usize) -> Rule<LockEvent<Actor, Path>> {
    nested(depth, "resource")
}
fn advancing_optional_rule(steps: usize) -> Rule<LockEvent<Actor, Path>> {
    authored(
        "optional",
        "require",
        "release",
        &text::concat((0..steps).map(|index| {
            format!(
                "(epsilon | event {{ resource != {} }})",
                ABSENT_IDS + index as u32
            )
        })),
    )
}
fn growing_residual_rule(window: usize) -> Rule<LockEvent<Actor, Path>> {
    assert!(window > 0);
    authored(
        "growing",
        "forbid",
        "release",
        &text::concat(
            ["all".into(), "event { action == action.read }".into()]
                .into_iter()
                .chain(std::iter::repeat_n("event { true }".to_owned(), window + 1)),
        ),
    )
}
fn absent_witness_rule(index: usize) -> Rule<LockEvent<Actor, Path>> {
    authored(
        &format!("absent_{index}"),
        "forbid",
        "release",
        &format!(
            "all >> event {{ principal == {} }} >> all",
            ABSENT_IDS + index as u32
        ),
    )
}

/// Untimed independent DSL oracle covering every synthetic fixture family.
pub fn textual_preflight() {
    use history_semantics::CompiledRule;
    use history_store::History;
    let pairs = [
        (prior_edit_rule(0), native_prior_edit_rule(0)),
        (duplicate_remove_rule(), native_duplicate_remove_rule()),
        (
            deeply_nested_allow_all_rule(32),
            native_deeply_nested_allow_all_rule(32),
        ),
        (
            deeply_nested_resource_allow_all_rule(32),
            native_deeply_nested_resource_allow_all_rule(32),
        ),
        (
            advancing_optional_rule(16),
            native_advancing_optional_rule(16),
        ),
        (growing_residual_rule(64), native_growing_residual_rule(64)),
        (absent_witness_rule(1023), native_absent_witness_rule(1023)),
    ];
    let alphabet = [
        LockEvent::new(ALICE, Action::Edit, ROOT),
        LockEvent::new(ALICE, Action::Read, ROOT),
        LockEvent::new(ALICE, Action::Remove, ROOT),
        LockEvent::new(HISTORY, Action::Release, ROOT),
        LockEvent::new(Actor(ABSENT_IDS), Action::Read, Path(ABSENT_IDS)),
    ];
    for (actual, expected) in pairs {
        let store = Arc::new(Store::new().unwrap());
        let mut actual = CompiledRule::new(store.clone(), actual).unwrap();
        let mut expected = CompiledRule::new(store.clone(), expected).unwrap();
        for length in 0..=3 {
            for mut word in 0..alphabet.len().pow(length) {
                let events = (0..length).map(|_| {
                    let event = alphabet[word % alphabet.len()];
                    word /= alphabet.len();
                    event
                });
                let history = History::from_events(store.clone(), events).unwrap();
                for action in [Action::Release, Action::Remove, Action::Read] {
                    let candidate = LockEvent::new(ALICE, action, ROOT);
                    assert_eq!(
                        actual.accepts_history(&history, &candidate).unwrap(),
                        expected.accepts_history(&history, &candidate).unwrap()
                    );
                }
            }
        }
    }
}

// The matching Require rule forces all one million committed events through the depth-32 tail.
fn benchmark_million_event_nested_scan(criterion: &mut Criterion) {
    const HISTORY_LEN: usize = 1_000_000;
    const REGEX_DEPTH: usize = 32;

    let store = Arc::new(Store::new().unwrap());
    let mut builder = Validator::builder(Arc::clone(&store));
    builder
        .add_rule(deeply_nested_allow_all_rule(REGEX_DEPTH))
        .expect("benchmark rule is valid");
    let mut validator = builder.finish().unwrap();
    for _ in 0..HISTORY_LEN {
        let _ = validator.check(request(ALICE, Action::Read, ROOT)).unwrap();
    }
    assert_eq!(validator.history().len(), HISTORY_LEN);
    let checkpoint = validator.checkpoint();

    let mut group = criterion.benchmark_group("full_scan");
    group.throughput(Throughput::Elements(HISTORY_LEN as u64));
    group.sample_size(10);
    group.bench_function("1000000_events/depth_32", |bencher| {
        bencher.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let candidate = request(ALICE, Action::Release, ROOT);
                let start = Instant::now();
                let decision = validator.check(black_box(candidate)).unwrap();
                elapsed += start.elapsed();
                assert!(decision.is_grant());
                validator.rollback(checkpoint).unwrap();
            }
            elapsed
        });
    });
    group.finish();
}

// Every history symbol is distinct, defeating symbol-indexed successor caches. Each leaf compares
// the event's resource with a constant no event carries, so every unique resource is compared.
fn benchmark_high_cardinality_scan(criterion: &mut Criterion) {
    const HISTORY_LEN: usize = 100_000;
    const REGEX_DEPTH: usize = 32;

    let store = Arc::new(Store::new().unwrap());
    let mut builder = Validator::builder(Arc::clone(&store));
    builder
        .add_rule(deeply_nested_resource_allow_all_rule(REGEX_DEPTH))
        .expect("benchmark rule is valid");
    let mut validator = builder.finish().unwrap();
    for index in 0..HISTORY_LEN {
        let _ = validator.check(unique_read(index)).unwrap();
    }
    assert_eq!(validator.history().len(), HISTORY_LEN);
    let checkpoint = validator.checkpoint();

    let mut group = criterion.benchmark_group("high_cardinality_scan");
    group.throughput(Throughput::Elements(HISTORY_LEN as u64));
    group.sample_size(10);
    group.bench_function("100000_events/depth_32", |bencher| {
        bencher.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let candidate = request(CANDIDATE, Action::Release, ROOT);
                let start = Instant::now();
                let decision = validator.check(black_box(candidate)).unwrap();
                elapsed += start.elapsed();
                assert!(decision.is_grant());
                validator.rollback(checkpoint).unwrap();
            }
            elapsed
        });
    });
    group.finish();
}

// Every derivative advances through a new suffix of a long concatenation of optional predicates.
// Symbol caches cannot reuse `(transition, symbol)` because the transition changes at every event.
fn benchmark_advancing_derivatives(criterion: &mut Criterion) {
    const STEPS: usize = 16;

    let store = Arc::new(Store::new().unwrap());
    let mut builder = Validator::builder(Arc::clone(&store));
    builder
        .add_rule(advancing_optional_rule(STEPS))
        .expect("benchmark rule is valid");
    let mut validator = builder.finish().unwrap();
    for _ in 0..STEPS {
        let _ = validator
            .check(request(HISTORY, Action::Read, ROOT))
            .unwrap();
    }
    let checkpoint = validator.checkpoint();

    let mut group = criterion.benchmark_group("advancing_derivatives");
    group.throughput(Throughput::Elements(STEPS as u64));
    group.sample_size(10);
    group.bench_function("16_optional_factors", |bencher| {
        bencher.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let candidate = request(CANDIDATE, Action::Release, ROOT);
                let start = Instant::now();
                let decision = validator.check(black_box(candidate)).unwrap();
                elapsed += start.elapsed();
                assert!(decision.is_grant());
                validator.rollback(checkpoint).unwrap();
            }
            elapsed
        });
    });
    group.finish();
}

fn benchmark_growing_residual_stress(criterion: &mut Criterion) {
    let mut compile = criterion.benchmark_group("stress_growing_residual_compile");
    compile
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(10);
    for window in [4_usize, 8, 12] {
        let source = growing_residual_rule(window);
        compile.bench_with_input(
            BenchmarkId::from_parameter(window),
            &window,
            |bencher, _| {
                bencher.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let source = source.clone();
                        let store = Arc::new(Store::new().unwrap());
                        let start = Instant::now();
                        let mut builder = Validator::builder(Arc::clone(&store));
                        builder.add_rule(source).expect("stress rule is valid");
                        let validator = builder.finish().unwrap();
                        black_box(&validator);
                        elapsed += start.elapsed();
                    }
                    elapsed
                });
            },
        );
    }
    compile.finish();

    let mut evaluate = criterion.benchmark_group("stress_growing_residual_evaluate");
    evaluate
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(10);
    for window in [8_usize, 16, 32, 64] {
        let store = Arc::new(Store::new().unwrap());
        let mut builder = Validator::builder(Arc::clone(&store));
        builder
            .add_rule(growing_residual_rule(window))
            .expect("stress rule is valid");
        let mut validator = builder.finish().unwrap();
        for _ in 0..window {
            assert!(
                validator
                    .check(request(HISTORY, Action::Read, EVENT))
                    .unwrap()
                    .is_grant()
            );
        }
        let checkpoint = validator.checkpoint();
        evaluate.throughput(Throughput::Elements(window as u64));
        evaluate.bench_with_input(
            BenchmarkId::from_parameter(window),
            &window,
            |bencher, _| {
                bencher.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let candidate = request(CANDIDATE, Action::Release, TARGET);
                        let start = Instant::now();
                        let decision = validator.check(black_box(candidate)).unwrap();
                        elapsed += start.elapsed();
                        assert!(decision.is_grant());
                        validator.rollback(checkpoint).unwrap();
                    }
                    elapsed
                });
            },
        );
    }
    evaluate.finish();
}

fn benchmark_many_rules_stress(criterion: &mut Criterion) {
    const HISTORY_LEN: usize = 64;
    const RULE_COUNTS: [usize; 5] = [1, 16, 64, 256, 1_024];

    let mut compile = criterion.benchmark_group("stress_many_rules_compile");
    compile
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(10);
    for rule_count in RULE_COUNTS {
        let rules = (0..rule_count).map(absent_witness_rule).collect::<Vec<_>>();
        compile.bench_with_input(
            BenchmarkId::from_parameter(rule_count),
            &rule_count,
            |bencher, _| {
                bencher.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let rules = rules.clone();
                        let store = Arc::new(Store::new().unwrap());
                        let start = Instant::now();
                        let mut builder = Validator::builder(Arc::clone(&store));
                        for rule in rules {
                            builder.add_rule(rule).expect("stress rule is valid");
                        }
                        let validator = builder.finish().unwrap();
                        black_box(&validator);
                        elapsed += start.elapsed();
                    }
                    elapsed
                });
            },
        );
    }
    compile.finish();

    let mut evaluate = criterion.benchmark_group("stress_many_rules_evaluate");
    evaluate
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(10);
    for rule_count in RULE_COUNTS {
        let store = Arc::new(Store::new().unwrap());
        let mut builder = Validator::builder(Arc::clone(&store));
        for index in 0..rule_count {
            builder
                .add_rule(absent_witness_rule(index))
                .expect("stress rule is valid");
        }
        let mut validator = builder.finish().unwrap();
        for _ in 0..HISTORY_LEN {
            assert!(
                validator
                    .check(request(HISTORY, Action::Read, EVENT))
                    .unwrap()
                    .is_grant()
            );
        }
        let checkpoint = validator.checkpoint();
        evaluate.throughput(Throughput::Elements(
            rule_count
                .checked_mul(HISTORY_LEN)
                .expect("stress work count fits u64") as u64,
        ));
        evaluate.bench_with_input(
            BenchmarkId::from_parameter(rule_count),
            &rule_count,
            |bencher, _| {
                bencher.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let candidate = request(CANDIDATE, Action::Release, TARGET);
                        let start = Instant::now();
                        let decision = validator.check(black_box(candidate)).unwrap();
                        elapsed += start.elapsed();
                        assert!(decision.is_grant());
                        validator.rollback(checkpoint).unwrap();
                    }
                    elapsed
                });
            },
        );
    }
    evaluate.finish();
}

fn benchmark_compilation(criterion: &mut Criterion) {
    textual_preflight();
    let mut group = criterion.benchmark_group("compile_rules");
    for count in [1_usize, 16, 64] {
        let rules = (0..count).map(prior_edit_rule).collect::<Vec<_>>();
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |bencher, _| {
            bencher.iter_custom(|iterations| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    let rules = rules.clone();
                    let store = Arc::new(Store::new().unwrap());
                    let start = Instant::now();
                    let mut builder = Validator::builder(Arc::clone(&store));
                    for rule in rules {
                        builder.add_rule(rule).expect("benchmark rule is valid");
                    }
                    let validator = builder.finish().unwrap();
                    black_box(&validator);
                    elapsed += start.elapsed();
                    drop(validator);
                }
                elapsed
            });
        });
    }
    group.finish();
}

fn validator_with_edit_history(
    store: Arc<Store<LockEvent<Actor, Path>>>,
    history_len: usize,
) -> Validator<LockEvent<Actor, Path>> {
    let mut builder = Validator::builder(store);
    builder
        .add_rule(prior_edit_rule(0))
        .expect("benchmark rule is valid");
    let mut validator = builder.finish().unwrap();
    for _ in 0..history_len {
        let decision = validator
            .check(request(ALICE, Action::Edit, SRC_A))
            .unwrap();
        assert!(decision.is_grant());
    }
    validator
}

fn benchmark_history_scan(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("history_scan");
    for history_len in [1_usize, 32, 256] {
        let store = Arc::new(Store::new().unwrap());
        let mut validator = validator_with_edit_history(Arc::clone(&store), history_len);
        let checkpoint = validator.checkpoint();
        group.bench_with_input(
            BenchmarkId::from_parameter(history_len),
            &history_len,
            |bencher, _| {
                bencher.iter_custom(|iterations| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let candidate = request(ALICE, Action::Release, SRC_A);
                        let start = Instant::now();
                        let decision = validator.check(black_box(candidate)).unwrap();
                        elapsed += start.elapsed();
                        assert!(decision.is_grant());
                        validator.rollback(checkpoint).unwrap();
                    }
                    elapsed
                });
            },
        );
    }
    group.finish();
}

fn benchmark_denial(criterion: &mut Criterion) {
    let store = Arc::new(Store::new().unwrap());
    let mut builder = Validator::builder(Arc::clone(&store));
    builder
        .add_rule(duplicate_remove_rule())
        .expect("benchmark rule is valid");
    let mut validator = builder.finish().unwrap();
    let first = validator.check(request(ALICE, Action::Remove, A)).unwrap();
    assert!(first.is_grant());

    criterion.bench_function("deny_duplicate_remove", |bencher| {
        bencher.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let candidate = request(ALICE, Action::Remove, A);
                let start = Instant::now();
                let decision = validator.check(black_box(candidate)).unwrap();
                elapsed += start.elapsed();
                assert!(matches!(decision, Decision::Denied(_)));
            }
            elapsed
        });
    });
}

fn benchmark_rollback(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("rollback");
    for removed_events in [1_usize, 64, 1024] {
        let rules: Vec<Rule<LockEvent<Actor, Path>>> = text::load(
            "junco 1; schema \"bench.lock/1\"; policy empty_policy {}",
            &text::LockVocabulary {
                principal: Actor,
                resource: Path,
            },
        );
        let store = Arc::new(Store::new().unwrap());
        group.bench_with_input(
            BenchmarkId::from_parameter(removed_events),
            &removed_events,
            |bencher, &removed_events| {
                bencher.iter_batched(
                    || {
                        let mut builder = Validator::builder(Arc::clone(&store));
                        for rule in rules.clone() {
                            builder.add_rule(rule).unwrap();
                        }
                        let mut validator = builder.finish().unwrap();
                        let checkpoint = validator.checkpoint();
                        for _ in 0..removed_events {
                            let decision =
                                validator.check(request(ALICE, Action::Read, A)).unwrap();
                            assert!(decision.is_grant());
                        }
                        (validator, checkpoint)
                    },
                    |(mut validator, checkpoint)| {
                        validator.rollback(checkpoint).unwrap();
                        black_box(validator);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    benchmark_compilation,
    benchmark_history_scan,
    benchmark_million_event_nested_scan,
    benchmark_high_cardinality_scan,
    benchmark_advancing_derivatives,
    benchmark_growing_residual_stress,
    benchmark_many_rules_stress,
    benchmark_denial,
    benchmark_rollback,
);
criterion_main!(benches);
