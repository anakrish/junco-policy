//! Translates standard regex syntax (parsed by `regex_syntax` in byte mode) into
//! Facts algebra text over `Symbol` events, one byte per event.

use crate::facts::Algebra as RegexText;
use history_facts::Schema;
use history_syntax::{Component3, Event, N3};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

/// One haystack byte as an open-domain resource, or the candidate triggering the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Symbol {
    Byte(u8),
    Candidate,
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
    pub regex: RegexText,
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
        regex: RegexText::concat(items.iter().map(|hir| emit(hir, pattern))),
        left,
        right,
    }
}

pub fn plain(pattern: &str) -> RegexText {
    let translated = translate(pattern);
    assert_eq!(translated.left, Edge::Open, "{pattern}");
    assert_eq!(translated.right, Edge::Open, "{pattern}");
    translated.regex
}

pub fn contains(regex: RegexText) -> RegexText {
    RegexText::concat([RegexText::all(), regex, RegexText::all()])
}

pub fn tail(translated: Translated) -> RegexText {
    let non_word = || class((0..=255u8).filter(|b| !(b.is_ascii_alphanumeric() || *b == b'_')));
    let left = match translated.left {
        Edge::Open => RegexText::all(),
        Edge::Anchored => RegexText::epsilon(),
        Edge::Word => RegexText::union([
            RegexText::epsilon(),
            RegexText::concat([RegexText::all(), non_word()]),
        ]),
    };
    let right = match translated.right {
        Edge::Open => RegexText::all(),
        Edge::Anchored => RegexText::epsilon(),
        Edge::Word => RegexText::union([
            RegexText::epsilon(),
            RegexText::concat([non_word(), RegexText::all()]),
        ]),
    };
    RegexText::concat([left, translated.regex, right])
}

pub fn class(members: impl IntoIterator<Item = u8>) -> RegexText {
    let mut table = [false; 256];
    for byte in members {
        table[usize::from(byte)] = true;
    }
    let count = table.iter().filter(|&&member| member).count();
    let atom = |comparison: &str, byte| format!("e.resource {comparison} byte.v{byte}");
    match count {
        0 => RegexText::empty(),
        256 => RegexText::event("true;"),
        1 => RegexText::event(&format!(
            "{};",
            atom("==", (0..=255u8).find(|&b| table[usize::from(b)]).unwrap(),)
        )),
        2..=128 => RegexText::event(&format!(
            "{};",
            (0..=255u8)
                .filter(|&b| table[usize::from(b)])
                .map(|b| atom("==", b))
                .collect::<Vec<_>>()
                .join(" or ")
        )),
        _ => RegexText::event(&format!(
            "{};",
            (0..=255u8)
                .filter(|&b| !table[usize::from(b)])
                .map(|b| atom("!=", b))
                .collect::<Vec<_>>()
                .join(" and ")
        )),
    }
}

pub fn literal(bytes: &[u8]) -> RegexText {
    RegexText::concat(bytes.iter().map(|&byte| class([byte])))
}

fn repeat(regex: RegexText, lo: u32, hi: Option<u32>) -> RegexText {
    let tail = match hi {
        None => Some(RegexText::star(regex.clone())),
        Some(hi) => {
            let mut tail = RegexText::epsilon();
            for _ in lo..hi {
                tail = RegexText::union([
                    RegexText::epsilon(),
                    RegexText::concat([regex.clone(), tail]),
                ]);
            }
            (lo < hi).then_some(tail)
        }
    };
    RegexText::concat((0..lo).map(|_| regex.clone()).chain(tail))
}

fn emit(hir: &Hir, pattern: &str) -> RegexText {
    match hir.kind() {
        HirKind::Empty => RegexText::epsilon(),
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
        HirKind::Alternation(items) => RegexText::union(items.iter().map(|hir| emit(hir, pattern))),
        HirKind::Concat(items) => RegexText::concat(items.iter().map(|hir| emit(hir, pattern))),
        HirKind::Look(_) => panic!("unsupported look inside {pattern}"),
    }
}

pub struct SymbolSchema;
impl Schema<Symbol> for SymbolSchema {
    fn name(&self) -> &str {
        "bytes"
    }
    fn field(&self, name: &str) -> Option<usize> {
        match name {
            "principal" => Some(0),
            "action" => Some(1),
            "resource" => Some(2),
            _ => None,
        }
    }
    fn constant(&self, name: &str) -> Option<Component3<(), (), Symbol>> {
        if name == "resource.candidate" {
            return Some(Component3::C2(Symbol::Candidate));
        }
        let byte = name.strip_prefix("byte.v")?.parse::<u8>().ok()?;
        Some(Component3::C2(Symbol::Byte(byte)))
    }
    fn diagnostic(&self, name: &str) -> bool {
        name == "benchmark.rule"
    }
}
