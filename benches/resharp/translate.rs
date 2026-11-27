//! Translates standard regex syntax (parsed by `regex_syntax` in byte mode) into
//! textual pipeline algebra over `Symbol` events, one byte per event.

use super::pipelines::Language as RegexExpr;
use history_pipeline::{Literal, Vocabulary};
use history_syntax::{Component, Component3, Event, N3};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

/// One haystack byte as an open-domain resource, or the candidate triggering the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Symbol {
    Byte(u8),
    Candidate,
}

pub struct Vocab;
impl Vocabulary<Symbol> for Vocab {
    fn schema(&self) -> &str {
        "Symbol"
    }
    fn fields(&self) -> &[&str] {
        &["principal", "action", "resource"]
    }
    fn constant(&self, field: Component, literal: &Literal) -> Option<Component3<(), (), Symbol>> {
        match (field.0, literal) {
            (0, Literal::Integer(0)) => Some(Component3::C0(())),
            (1, Literal::Integer(0)) => Some(Component3::C1(())),
            (2, Literal::Integer(n)) => u8::try_from(*n)
                .ok()
                .map(|n| Component3::C2(Symbol::Byte(n))),
            (2, Literal::String(s)) if s == "candidate" => Some(Component3::C2(Symbol::Candidate)),
            _ => None,
        }
    }
}
// Unverified glue: `hash_respects_eq` is a hypothesis for this type (as `event_laws` already is).
impl history_syntax::KeyHash for Symbol {
    fn key_hash(&self) -> u64 {
        history_syntax::key_hash::hash_via_std(self)
    }
}

impl Event for Symbol {
    type Component = Component3<(), (), Symbol>;
    type Arity = N3;

    fn component(self, index: usize) -> Self::Component {
        match index {
            0 => Component3::C0(()),
            1 => Component3::C1(()),
            _ => Component3::C2(self),
        }
    }

    fn coordinate(component: Self::Component) -> usize {
        match component {
            Component3::C0(_) => 0,
            Component3::C1(_) => 1,
            Component3::C2(_) => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edge {
    Open,
    Anchored,
    Word,
}

pub struct Translated {
    pub regex: RegexExpr<Symbol>,
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
    // shortcut: \b is honoured only at pattern edges next to a word character (all RE# corpus
    // patterns); generalize if an interior \b is ever ported
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
        regex: RegexExpr::concat(items.iter().map(|hir| emit(hir, pattern))),
        left,
        right,
    }
}

pub fn plain(pattern: &str) -> RegexExpr<Symbol> {
    let translated = translate(pattern);
    assert_eq!(translated.left, Edge::Open, "{pattern}");
    assert_eq!(translated.right, Edge::Open, "{pattern}");
    translated.regex
}

pub fn contains(regex: RegexExpr<Symbol>) -> RegexExpr<Symbol> {
    RegexExpr::concat([RegexExpr::all(), regex, RegexExpr::all()])
}

pub fn tail(translated: Translated) -> RegexExpr<Symbol> {
    let non_word = || class((0..=255u8).filter(|b| !(b.is_ascii_alphanumeric() || *b == b'_')));
    let left = match translated.left {
        Edge::Open => RegexExpr::all(),
        Edge::Anchored => RegexExpr::epsilon(),
        Edge::Word => RegexExpr::union([
            RegexExpr::epsilon(),
            RegexExpr::concat([RegexExpr::all(), non_word()]),
        ]),
    };
    let right = match translated.right {
        Edge::Open => RegexExpr::all(),
        Edge::Anchored => RegexExpr::epsilon(),
        Edge::Word => RegexExpr::union([
            RegexExpr::epsilon(),
            RegexExpr::concat([non_word(), RegexExpr::all()]),
        ]),
    };
    RegexExpr::concat([left, translated.regex, right])
}

pub fn class(members: impl IntoIterator<Item = u8>) -> RegexExpr<Symbol> {
    let mut table = [false; 256];
    for byte in members {
        table[usize::from(byte)] = true;
    }
    let count = table.iter().filter(|&&member| member).count();
    match count {
        0 => RegexExpr::empty(),
        256 => RegexExpr::test("true"),
        1 => RegexExpr::test(format!(
            "resource == {}",
            (0..=255u8).find(|&b| table[usize::from(b)]).unwrap()
        )),
        2..=128 => RegexExpr::test(format!(
            "any_of({})",
            (0..=255u8)
                .filter(|&b| table[usize::from(b)])
                .map(|b| format!("resource == {b}"))
                .collect::<Vec<_>>()
                .join(",")
        )),
        _ => RegexExpr::test(format!(
            "all_of({})",
            (0..=255u8)
                .filter(|&b| !table[usize::from(b)])
                .map(|b| format!("resource != {b}"))
                .collect::<Vec<_>>()
                .join(",")
        )),
    }
}

pub fn literal(bytes: &[u8]) -> RegexExpr<Symbol> {
    RegexExpr::concat(bytes.iter().map(|&byte| class([byte])))
}

fn repeat(regex: RegexExpr<Symbol>, lo: u32, hi: Option<u32>) -> RegexExpr<Symbol> {
    let tail = match hi {
        None => Some(RegexExpr::star(regex.clone())),
        Some(hi) => {
            let mut tail = RegexExpr::epsilon();
            for _ in lo..hi {
                tail = RegexExpr::union([
                    RegexExpr::epsilon(),
                    RegexExpr::concat([regex.clone(), tail]),
                ]);
            }
            (lo < hi).then_some(tail)
        }
    };
    RegexExpr::concat((0..lo).map(|_| regex.clone()).chain(tail))
}

fn emit(hir: &Hir, pattern: &str) -> RegexExpr<Symbol> {
    match hir.kind() {
        HirKind::Empty => RegexExpr::epsilon(),
        HirKind::Literal(lit) => literal(&lit.0),
        HirKind::Class(Class::Bytes(bytes)) => class(
            bytes
                .ranges()
                .iter()
                .flat_map(|range| range.start()..=range.end()),
        ),
        HirKind::Class(Class::Unicode(_)) => unreachable!("byte mode yields byte classes"),
        HirKind::Repetition(rep) => repeat(emit(&rep.sub, pattern), rep.min, rep.max),
        HirKind::Capture(capture) => emit(&capture.sub, pattern),
        HirKind::Alternation(items) => RegexExpr::union(items.iter().map(|hir| emit(hir, pattern))),
        HirKind::Concat(items) => RegexExpr::concat(items.iter().map(|hir| emit(hir, pattern))),
        HirKind::Look(_) => panic!("unsupported look inside {pattern}"),
    }
}
