//! Byte-mode standard regex HIR -> explicit Junco Text, never a native factory.
pub use super::native_translate::{Edge, Symbol};
use super::text::Expression as Regex;
use history_syntax::{Component, Component3};
use history_text::{CoordinateSpec, Literal, Resolver, Vocabulary};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

pub struct Translated {
    pub regex: Regex,
    pub left: Edge,
    pub right: Edge,
}
pub fn translate(pattern: &str) -> Translated {
    let hir = regex_syntax::ParserBuilder::new()
        .utf8(false)
        .unicode(false)
        .build()
        .parse(pattern)
        .expect(pattern);
    let mut items = match hir.kind() {
        HirKind::Concat(items) => items.as_slice(),
        _ => std::slice::from_ref(&hir),
    };
    let left = match items.first().map(Hir::kind) {
        Some(HirKind::Look(Look::Start)) => Edge::Anchored,
        Some(HirKind::Look(Look::WordAscii)) => Edge::Word,
        _ => Edge::Open,
    };
    if left != Edge::Open {
        items = &items[1..];
    }
    let right = match items.last().map(Hir::kind) {
        Some(HirKind::Look(Look::End)) => Edge::Anchored,
        Some(HirKind::Look(Look::WordAscii)) => Edge::Word,
        _ => Edge::Open,
    };
    if right != Edge::Open {
        items = &items[..items.len() - 1];
    }
    Translated {
        regex: Regex::concat(items.iter().map(|hir| emit(hir, pattern))),
        left,
        right,
    }
}
pub fn plain(pattern: &str) -> Regex {
    let translated = translate(pattern);
    assert_eq!(translated.left, Edge::Open, "{pattern}");
    assert_eq!(translated.right, Edge::Open, "{pattern}");
    translated.regex
}
pub fn contains(regex: Regex) -> Regex {
    Regex::concat([Regex::all(), regex, Regex::all()])
}
pub fn tail(translated: Translated) -> Regex {
    let non_word = || class((0..=255u8).filter(|b| !(b.is_ascii_alphanumeric() || *b == b'_')));
    let left = match translated.left {
        Edge::Open => Regex::all(),
        Edge::Anchored => Regex::epsilon(),
        Edge::Word => Regex::union([Regex::epsilon(), Regex::concat([Regex::all(), non_word()])]),
    };
    let right = match translated.right {
        Edge::Open => Regex::all(),
        Edge::Anchored => Regex::epsilon(),
        Edge::Word => Regex::union([Regex::epsilon(), Regex::concat([non_word(), Regex::all()])]),
    };
    Regex::concat([left, translated.regex, right])
}
pub fn class(members: impl IntoIterator<Item = u8>) -> Regex {
    let mut table = [false; 256];
    for byte in members {
        table[usize::from(byte)] = true;
    }
    let count = table.iter().filter(|&&member| member).count();
    let atom = |equal: bool, byte| format!("resource {} {byte}", if equal { "==" } else { "!=" });
    match count {
        0 => Regex::empty(),
        // Intentionally open-domain: Candidate also satisfies the native True.
        256 => Regex("event { true }".into()),
        1 => Regex(format!(
            "event {{ {} }}",
            atom(true, (0..=255u8).find(|&b| table[usize::from(b)]).unwrap())
        )),
        2..=128 => Regex(format!(
            "event {{ {} }}",
            (0..=255u8)
                .filter(|&b| table[usize::from(b)])
                .map(|b| atom(true, b))
                .collect::<Vec<_>>()
                .join(" or ")
        )),
        _ => Regex(format!(
            "event {{ {} }}",
            (0..=255u8)
                .filter(|&b| !table[usize::from(b)])
                .map(|b| atom(false, b))
                .collect::<Vec<_>>()
                .join(" and ")
        )),
    }
}
pub fn literal(bytes: &[u8]) -> Regex {
    Regex::concat(bytes.iter().map(|&byte| class([byte])))
}
fn repeat(regex: Regex, lo: u32, hi: Option<u32>) -> Regex {
    let tail = match hi {
        None => Some(Regex::star(regex.clone())),
        Some(hi) => {
            let mut tail = Regex::epsilon();
            for _ in lo..hi {
                tail = Regex::union([Regex::epsilon(), Regex::concat([regex.clone(), tail])]);
            }
            (lo < hi).then_some(tail)
        }
    };
    Regex::concat((0..lo).map(|_| regex.clone()).chain(tail))
}
fn emit(hir: &Hir, pattern: &str) -> Regex {
    match hir.kind() {
        HirKind::Empty => Regex::epsilon(),
        HirKind::Literal(lit) => literal(&lit.0),
        HirKind::Class(Class::Bytes(bytes)) => class(
            bytes
                .ranges()
                .iter()
                .flat_map(|range| range.start()..=range.end()),
        ),
        HirKind::Class(Class::Unicode(_)) => {
            panic!("unexpected Unicode class in byte-mode pattern {pattern}")
        }
        HirKind::Repetition(rep) => repeat(emit(&rep.sub, pattern), rep.min, rep.max),
        HirKind::Capture(capture) => emit(&capture.sub, pattern),
        HirKind::Alternation(items) => Regex::union(items.iter().map(|hir| emit(hir, pattern))),
        HirKind::Concat(items) => Regex::concat(items.iter().map(|hir| emit(hir, pattern))),
        HirKind::Look(_) => panic!("unsupported look inside {pattern}"),
    }
}

pub struct ByteVocabulary;
const COORDINATES: [CoordinateSpec<'static>; 3] = [
    CoordinateSpec {
        name: "principal",
        domain: "unit",
        literals: super::text::SYMBOLS,
    },
    CoordinateSpec {
        name: "action",
        domain: "unit",
        literals: super::text::SYMBOLS,
    },
    CoordinateSpec {
        name: "resource",
        domain: "byte-or-candidate",
        literals: super::text::IDS,
    },
];
impl Resolver<Symbol> for ByteVocabulary {
    type Error = &'static str;
    fn vocabulary(&self) -> Vocabulary<'_> {
        Vocabulary {
            id: "bench.byte/1",
            coordinates: &COORDINATES,
        }
    }
    fn resolve(
        &self,
        coordinate: Component,
        literal: Literal<'_>,
    ) -> Result<Component3<(), (), Symbol>, Self::Error> {
        match (coordinate.index(), literal) {
            (2, Literal::Integer(s)) => Ok(Component3::C2(Symbol::Byte(
                s.parse().map_err(|_| "invalid byte")?,
            ))),
            (2, Literal::Symbol("candidate")) => Ok(Component3::C2(Symbol::Candidate)),
            _ => Err("unsupported byte vocabulary value"),
        }
    }
}
pub fn rule(regex: Regex) -> history_syntax::Rule<Symbol> {
    let source = format!(
        "junco 1; schema \"bench.byte/1\"; policy byte_regex {{
        rule matches {{ candidate {{ principal: $P, action: $A, resource: resource.candidate }};
        require {}; }} }}",
        regex.0
    );
    let mut rules = super::text::load(&source, &ByteVocabulary);
    assert_eq!(rules.len(), 1);
    rules.pop().unwrap()
}

pub fn equivalent(actual: Regex, expected: history_syntax::RegexExpr<Symbol>) {
    use history_semantics::CompiledRule;
    use history_store::{History, Store};
    use history_syntax::{ComponentPattern, Head, Rule, RuleMode};
    use std::sync::Arc;
    let store = Arc::new(Store::new().unwrap());
    let source = rule(actual);
    let head = Head::new([
        ComponentPattern::variable("P"),
        ComponentPattern::variable("A"),
        ComponentPattern::Constant(Component3::C2(Symbol::Candidate)),
    ]);
    let mut actual = CompiledRule::new(store.clone(), source).unwrap();
    let mut expected =
        CompiledRule::new(store.clone(), Rule::new(RuleMode::Require, head, expected)).unwrap();
    let alphabet = [
        Symbol::Byte(0),
        Symbol::Byte(b'a'),
        Symbol::Byte(b'_'),
        Symbol::Byte(b'\n'),
        Symbol::Byte(255),
        Symbol::Candidate,
    ];
    for length in 0..=2 {
        for mut word in 0..alphabet.len().pow(length) {
            let events = (0..length).map(|_| {
                let event = alphabet[word % alphabet.len()];
                word /= alphabet.len();
                event
            });
            let history = History::from_events(store.clone(), events).unwrap();
            assert_eq!(
                actual
                    .accepts_history(&history, &Symbol::Candidate)
                    .unwrap(),
                expected
                    .accepts_history(&history, &Symbol::Candidate)
                    .unwrap()
            );
        }
        for sample in [
            b"<script>x</script>".as_slice(),
            b"<SCRIPT><script></script></SCRIPT>",
            b" deleted_at ",
            b"_deleted_at_",
            b"P@ssw0rd!",
            b"valid123",
            b"---",
            b"7.3kg",
            b"<a x=\"v\"  target=x>",
            b" Sherlock ",
            b"abc",
            b"",
        ] {
            let history =
                History::from_events(store.clone(), sample.iter().copied().map(Symbol::Byte))
                    .unwrap();
            assert_eq!(
                actual
                    .accepts_history(&history, &Symbol::Candidate)
                    .unwrap(),
                expected
                    .accepts_history(&history, &Symbol::Candidate)
                    .unwrap(),
                "{sample:?}"
            );
        }
    }
}
