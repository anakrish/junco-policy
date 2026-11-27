//! Benchmark source templates. These build text directly, never a native policy AST.
#![allow(dead_code)]

use history_pipeline::{Limits, Literal, Vocabulary, lower, parse};
use history_syntax::{Component, Event, Rule};
use junco_policy::{Action, LockComponent, LockEvent};
use std::marker::PhantomData;

/// Flat typed history-algebra instruction text, not an evaluator or native AST.
#[derive(Debug)]
pub struct Language<E> {
    pub text: String,
    marker: PhantomData<fn() -> E>,
}

impl<E> Clone for Language<E> {
    fn clone(&self) -> Self {
        Self::new(self.text.clone())
    }
}

impl<E> Language<E> {
    pub fn new(text: String) -> Self {
        Self {
            text,
            marker: PhantomData,
        }
    }
    pub fn all() -> Self {
        Self::new("any;".into())
    }
    pub fn epsilon() -> Self {
        Self::new("empty;".into())
    }
    pub fn empty() -> Self {
        Self::new("never;".into())
    }
    pub fn test(predicate: impl AsRef<str>) -> Self {
        Self::new(format!("single (Event | where {});", predicate.as_ref()))
    }
    pub fn concat(items: impl IntoIterator<Item = Self>) -> Self {
        Self::combine(items, "concat")
    }
    pub fn union(items: impl IntoIterator<Item = Self>) -> Self {
        Self::combine(items, "choice")
    }
    pub fn intersect(items: impl IntoIterator<Item = Self>) -> Self {
        Self::combine(items, "intersection")
    }
    fn combine(items: impl IntoIterator<Item = Self>, operator: &str) -> Self {
        let mut text = String::new();
        let mut count = 0;
        for item in items {
            text.push_str(&item.text);
            count += 1;
        }
        text.push_str(&format!("{operator} {count};"));
        Self::new(text)
    }
    pub fn star(mut item: Self) -> Self {
        item.text.push_str("star;");
        item
    }
    pub fn complement(mut item: Self) -> Self {
        item.text.push_str("negate;");
        item
    }
}

pub fn limits() -> Limits {
    Limits {
        source_bytes: 262_144,
        tokens: 32_768,
        literal_bytes: 4_096,
        nesting: 64,
        nodes: 65_536,
        rules: 512,
    }
}

pub fn load<E: Event>(source: &str, vocabulary: &impl Vocabulary<E>) -> Vec<Rule<E>> {
    lower(
        parse(source, vocabulary, limits())
            .expect("benchmark textual source parses and typechecks"),
    )
    .into_iter()
    .map(|item| item.rule)
    .collect()
}

pub fn language_rule<E: Event>(
    language: Language<E>,
    vocabulary: &impl Vocabulary<E>,
    selector: &str,
    mode: &str,
) -> Rule<E> {
    let fields = vocabulary.fields().join(",");
    let source = format!(
        "schema {}({fields}); rule Benchmark = {selector} | {mode} History | algebra {{ {} }} | deny \"benchmark\";",
        vocabulary.schema(),
        language.text
    );
    load(&source, vocabulary).pop().expect("one textual rule")
}

pub struct LockVocabulary<P, R>(pub fn(u32) -> P, pub fn(u32) -> R);

impl<P, R> Vocabulary<LockEvent<P, R>> for LockVocabulary<P, R>
where
    P: Copy + std::fmt::Debug + Eq + std::hash::Hash,
    R: Copy + std::fmt::Debug + Eq + std::hash::Hash,
{
    fn schema(&self) -> &str {
        "Lock"
    }
    fn fields(&self) -> &[&str] {
        &["principal", "action", "resource"]
    }
    fn constant(&self, field: Component, literal: &Literal) -> Option<LockComponent<P, R>> {
        match (field.0, literal) {
            (0, Literal::Integer(n)) => u32::try_from(*n)
                .ok()
                .map(|n| LockComponent::Principal((self.0)(n))),
            (2, Literal::Integer(n)) => u32::try_from(*n)
                .ok()
                .map(|n| LockComponent::Resource((self.1)(n))),
            (1, Literal::String(s)) => match s.as_str() {
                "read" => Some(Action::Read),
                "edit" => Some(Action::Edit),
                "release" => Some(Action::Release),
                "remove" => Some(Action::Remove),
                _ => None,
            }
            .map(LockComponent::Action),
            _ => None,
        }
    }
}

pub const RELEASE: &str = "Candidate | bind principal=p, resource=r | where action == \"release\"";
pub const TERMINAL_EDIT: &str = include_str!("terminal-edit.pipeline");
pub const PRIOR_EDIT: &str = include_str!("prior-edit.pipeline");
pub const APPROVAL: &str = include_str!("approval.pipeline");
pub const DUPLICATE_REMOVE: &str = include_str!("duplicate-remove.pipeline");

pub fn one<P, R>(source: &str, p: fn(u32) -> P, r: fn(u32) -> R) -> Rule<LockEvent<P, R>>
where
    P: Copy + std::fmt::Debug + Eq + std::hash::Hash,
    R: Copy + std::fmt::Debug + Eq + std::hash::Hash,
{
    load(source, &LockVocabulary(p, r))
        .pop()
        .expect("one textual rule")
}

pub fn nested<P, R>(
    depth: usize,
    field: &str,
    absent: u32,
    p: fn(u32) -> P,
    r: fn(u32) -> R,
) -> Rule<LockEvent<P, R>>
where
    P: Copy + std::fmt::Debug + Eq + std::hash::Hash,
    R: Copy + std::fmt::Debug + Eq + std::hash::Hash,
{
    assert!(depth > 0);
    let leaf = |i| Language::star(Language::test(format!("{field} != {}", absent + i as u32)));
    let mut text = leaf(0);
    for i in 1..depth {
        text = if (i - 1) % 2 == 0 {
            Language::union([text, leaf(i)])
        } else {
            Language::intersect([text, leaf(i)])
        };
    }
    language_rule(text, &LockVocabulary(p, r), RELEASE, "require")
}

pub fn optional<P, R>(
    steps: usize,
    absent: u32,
    p: fn(u32) -> P,
    r: fn(u32) -> R,
) -> Rule<LockEvent<P, R>>
where
    P: Copy + std::fmt::Debug + Eq + std::hash::Hash,
    R: Copy + std::fmt::Debug + Eq + std::hash::Hash,
{
    language_rule(
        Language::concat((0..steps).map(|i| {
            Language::union([
                Language::epsilon(),
                Language::test(format!("resource != {}", absent + i as u32)),
            ])
        })),
        &LockVocabulary(p, r),
        RELEASE,
        "require",
    )
}

pub fn growing<P, R>(window: usize, p: fn(u32) -> P, r: fn(u32) -> R) -> Rule<LockEvent<P, R>>
where
    P: Copy + std::fmt::Debug + Eq + std::hash::Hash,
    R: Copy + std::fmt::Debug + Eq + std::hash::Hash,
{
    assert!(window > 0);
    language_rule(
        Language::concat(
            std::iter::once(Language::all())
                .chain(std::iter::once(Language::test("action == \"read\"")))
                .chain(std::iter::repeat_n(Language::test("true"), window + 1)),
        ),
        &LockVocabulary(p, r),
        RELEASE,
        "forbid",
    )
}

pub fn absent<P, R>(id: u32, p: fn(u32) -> P, r: fn(u32) -> R) -> Rule<LockEvent<P, R>>
where
    P: Copy + std::fmt::Debug + Eq + std::hash::Hash,
    R: Copy + std::fmt::Debug + Eq + std::hash::Hash,
{
    language_rule(
        Language::concat([
            Language::all(),
            Language::test(format!("principal == {id}")),
            Language::all(),
        ]),
        &LockVocabulary(p, r),
        RELEASE,
        "forbid",
    )
}
