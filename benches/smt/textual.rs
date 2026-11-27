//! Textual corpus recipes. Class representatives are data; no native factory
//! participates in generating the authoritative source.
use super::regexlib_subset::{ALPHABET, CLASSES, Char};
use super::text::Expression as R;
use history_syntax::{Component, Component3};
use history_text::{CoordinateSpec, Literal, Resolver, Vocabulary};

fn class(index: usize) -> R {
    R(format!(
        "event {{ {} }}",
        CLASSES[index]
            .iter()
            .map(|rep| format!("action == {rep}"))
            .collect::<Vec<_>>()
            .join(" or ")
    ))
}
fn opt(regex: R) -> R {
    R::union([R::epsilon(), regex])
}
fn plus(regex: R) -> R {
    R::concat([regex.clone(), R::star(regex)])
}
fn repeat(regex: R, lo: usize, hi: usize) -> R {
    let mut tail = R::epsilon();
    for _ in lo..hi {
        tail = opt(R::concat([regex.clone(), tail]));
    }
    R::concat(
        (0..lo)
            .map(|_| regex.clone())
            .chain((lo < hi).then_some(tail)),
    )
}

pub fn expression(index: usize) -> R {
    assert!(index < 20);
    let changed = index >= 10;
    let word = if changed { 23 } else { 0 };
    let digits = if changed { 24 } else { 8 };
    let alnum = if changed { 25 } else { 13 };
    let letters = if changed { 26 } else { 14 };
    let word_dash = if changed { 27 } else { 15 };
    let email = |w| {
        R::concat([
            plus(class(w)),
            R::star(R::concat([class(1), plus(class(w))])),
            class(2),
            plus(class(w)),
            R::star(R::concat([class(3), plus(class(w))])),
            class(4),
            plus(class(w)),
            R::star(R::concat([class(3), plus(class(w))])),
        ])
    };
    match index % 10 {
        0 => R::concat([
            email(word),
            R::star(R::concat([class(5), R::star(class(6)), email(word)])),
        ]),
        1 => R::concat([
            opt(class(7)),
            R::union([
                R::concat([
                    repeat(class(digits), 1, 3),
                    opt(class(9)),
                    R::star(R::concat([repeat(class(digits), 3, 3), opt(class(9))])),
                    repeat(class(digits), 3, 3),
                    opt(R::concat([class(4), repeat(class(digits), 0, 2)])),
                ]),
                R::concat([
                    repeat(class(digits), 1, 3),
                    opt(R::concat([class(4), repeat(class(digits), 0, 2)])),
                ]),
                R::concat([class(4), opt(repeat(class(digits), 1, 2))]),
            ]),
        ]),
        2 => R::concat([
            opt(R::union([
                repeat(class(10), 2, 2),
                R::concat([
                    repeat(class(11), 2, 2),
                    class(12),
                    repeat(class(digits), 2, 2),
                    class(12),
                    repeat(class(10), 1, 2),
                ]),
                R::concat([
                    repeat(class(11), 1, 2),
                    class(12),
                    repeat(class(digits), 1, 4),
                ]),
            ])),
            opt(R::union([
                repeat(class(10), 3, 3),
                R::concat([
                    repeat(class(11), 3, 3),
                    class(12),
                    repeat(class(digits), 1, 4),
                ]),
            ])),
        ]),
        3 => R::concat([
            class(alnum),
            R::star(R::concat([opt(class(3)), plus(class(alnum))])),
            class(2),
            plus(class(alnum)),
            R::star(R::concat([opt(class(3)), plus(class(alnum))])),
            class(letters),
            plus(class(letters)),
        ]),
        4 => R::concat([
            plus(class(word_dash)),
            class(2),
            plus(R::concat([plus(class(word_dash)), class(4)])),
            plus(class(word_dash)),
        ]),
        5 => {
            let d = if changed { 28 } else { 8 };
            R::concat([
                opt(class(16)),
                R::union([
                    R::concat([R::star(class(d)), opt(class(4)), plus(class(d))]),
                    R::concat([plus(class(d)), opt(class(4)), R::star(class(d))]),
                ]),
                opt(R::concat([class(17), opt(class(16)), plus(class(d))])),
            ])
        }
        6 => {
            let (a, b, c, d) = if changed {
                (29, 30, 31, 32)
            } else {
                (18, 15, 13, 19)
            };
            R::concat([
                plus(class(a)),
                class(2),
                R::union([
                    repeat(class(b), 1, 67),
                    R::concat([plus(class(b)), class(4), repeat(class(b), 1, 67)]),
                ]),
                class(4),
                repeat(class(c), 2, 4),
                opt(R::concat([class(4), repeat(class(d), 2, 2)])),
            ])
        }
        7 => R::concat([
            R::star(R::union([
                R::concat([plus(class(13)), plus(class(12))]),
                R::concat([plus(class(13)), plus(class(20))]),
                R::concat([plus(class(13)), plus(class(4))]),
                R::concat([plus(class(13)), plus(class(21))]),
            ])),
            plus(class(13)),
            class(2),
            R::star(R::union([
                R::concat([plus(class(word)), plus(class(20))]),
                R::concat([plus(class(word)), class(4)]),
            ])),
            repeat(class(word), 1, 63),
            class(4),
            repeat(class(14), 2, 6),
        ]),
        8 => {
            let a = if changed { 33 } else { 22 };
            let part = || {
                plus(R::concat([
                    plus(class(a)),
                    class(2),
                    plus(class(a)),
                    class(4),
                    repeat(repeat(class(letters), 2, 5), 1, 25),
                ]))
            };
            R::concat([part(), R::star(part())])
        }
        9 => plus(R::concat([
            email(word),
            R::star(class(6)),
            opt(class(9)),
            R::star(class(6)),
        ])),
        _ => unreachable!(),
    }
}

struct CharVocabulary;
const COORDINATES: [CoordinateSpec<'static>; 3] = [
    CoordinateSpec {
        name: "principal",
        domain: "unit",
        literals: super::text::SYMBOLS,
    },
    CoordinateSpec {
        name: "action",
        domain: "corpus-character",
        literals: super::text::IDS,
    },
    CoordinateSpec {
        name: "resource",
        domain: "unit",
        literals: super::text::SYMBOLS,
    },
];
impl Resolver<Char> for CharVocabulary {
    type Error = &'static str;
    fn vocabulary(&self) -> Vocabulary<'_> {
        Vocabulary {
            id: "bench.regexlib/1",
            coordinates: &COORDINATES,
        }
    }
    fn resolve(
        &self,
        coordinate: Component,
        literal: Literal<'_>,
    ) -> Result<Component3<(), u8, ()>, Self::Error> {
        match (coordinate.index(), literal) {
            (0, Literal::Symbol("unit")) => Ok(Component3::C0(())),
            (2, Literal::Symbol("unit")) => Ok(Component3::C2(())),
            (1, Literal::Integer(s)) => Ok(Component3::C1(
                s.parse().map_err(|_| "invalid corpus byte")?,
            )),
            _ => Err("unsupported corpus constant"),
        }
    }
}
pub fn rule(index: usize) -> history_syntax::Rule<Char> {
    let text = format!("junco 1; schema \"bench.regexlib/1\"; policy corpus {{
        rule matches {{ candidate {{ principal: principal.unit, action: {}, resource: resource.unit }};
        forbid {}; }} }}", ALPHABET[0], expression(index).0);
    let mut rules = super::text::load(&text, &CharVocabulary);
    assert_eq!(rules.len(), 1);
    rules.pop().unwrap()
}

pub fn preflight() {
    use history_semantics::CompiledRule;
    use history_store::{History, Store};
    use history_syntax::{Rule, RuleMode};
    use std::sync::Arc;
    let mut oracles = std::collections::BTreeMap::new();
    for instance in &super::regexlib_subset::INSTANCES {
        let (left, right) = indices(instance.file);
        oracles.insert(left, instance.left);
        oracles.insert(right, instance.right);
    }
    assert_eq!(oracles.len(), 20);
    for (index, oracle) in oracles {
        let store = Arc::new(Store::new().unwrap());
        let source = rule(index);
        let domains = history_analysis::Domains::<Char>::infinite()
            .with_domain(Component(0), &[Component3::C0(())])
            .unwrap()
            .with_domain(Component(1), &ALPHABET.map(Component3::C1))
            .unwrap()
            .with_domain(Component(2), &[Component3::C2(())])
            .unwrap();
        let mut analyzer = history_analysis::PolicyAnalyzer::new(domains);
        let native = oracle();
        assert!(
            matches!(
                analyzer
                    .tail_included(&source.head, &source.tail, &native)
                    .unwrap(),
                history_analysis::Inclusion::Holds
            ),
            "text subset native {index}"
        );
        assert!(
            matches!(
                analyzer
                    .tail_included(&source.head, &native, &source.tail)
                    .unwrap(),
                history_analysis::Inclusion::Holds
            ),
            "native subset text {index}"
        );
        let mut expected = CompiledRule::new(
            store.clone(),
            Rule::new(RuleMode::Forbid, source.head.clone(), oracle()),
        )
        .unwrap();
        let mut actual = CompiledRule::new(store.clone(), source).unwrap();
        let candidate = Char(ALPHABET[0]);
        let alphabet = [0u8, b'0', b'1', b'a', b'b', b'@', b'.', b' ', 255];
        for length in 0..=2 {
            for mut word in 0..alphabet.len().pow(length) {
                let history = History::from_events(
                    store.clone(),
                    (0..length).map(|_| {
                        let c = Char(alphabet[word % alphabet.len()]);
                        word /= alphabet.len();
                        c
                    }),
                )
                .unwrap();
                assert_eq!(
                    actual.accepts_history(&history, &candidate).unwrap(),
                    expected.accepts_history(&history, &candidate).unwrap(),
                    "regex {index}"
                );
            }
        }
    }
}
pub fn indices(file: &str) -> (usize, usize) {
    let (kind, name) = file.split_once('/').unwrap();
    let pair = name
        .strip_prefix("notsubset_")
        .unwrap()
        .strip_suffix(".smt2")
        .unwrap();
    let (left, right) = pair.split_once('_').unwrap();
    (
        left.parse::<usize>().unwrap() + if kind == "unsat" { 10 } else { 0 },
        right.parse().unwrap(),
    )
}
