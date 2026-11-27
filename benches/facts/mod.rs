//! Benchmark-local source authoring helpers. Algebra holds text, never a native AST.
//! All loaders run before the existing kernel timers.
#![allow(dead_code)]

use history_facts::{Limits, Schema, lower, parse};
use history_syntax::{Event, Rule};

#[derive(Clone)]
pub struct Algebra(pub String);

impl Algebra {
    pub fn all() -> Self {
        Self("all;".into())
    }
    pub fn empty() -> Self {
        Self("empty;".into())
    }
    pub fn epsilon() -> Self {
        Self("epsilon;".into())
    }
    pub fn event(body: &str) -> Self {
        Self(format!("event e {{ {body} }};"))
    }
    pub fn concat(items: impl IntoIterator<Item = Self>) -> Self {
        Self::combine("concat", items)
    }
    pub fn union(items: impl IntoIterator<Item = Self>) -> Self {
        Self::combine("union", items)
    }
    pub fn intersect(items: impl IntoIterator<Item = Self>) -> Self {
        Self::combine("intersect", items)
    }
    fn combine(op: &str, items: impl IntoIterator<Item = Self>) -> Self {
        let mut text = String::new();
        let mut count = 0usize;
        for item in items {
            text.push_str(&item.0);
            count += 1;
        }
        text.push_str(&format!("{op} count.{count};"));
        Self(text)
    }
    pub fn star(item: Self) -> Self {
        Self(format!("{}star;", item.0))
    }
    pub fn complement(item: Self) -> Self {
        Self(format!("{}complement;", item.0))
    }
}

pub fn rules<E: Event>(text: &str, schema: &impl Schema<E>) -> Vec<Rule<E>> {
    let module = parse(text, Limits::default()).expect("benchmark Facts source parses");
    lower(&module, schema, Limits::default())
        .expect("benchmark Facts source typechecks")
        .obligations
        .into_iter()
        .map(|o| o.rule)
        .collect()
}

pub fn rule<E: Event>(tail: Algebra, mode: &str, head: &str, schema: &impl Schema<E>) -> Rule<E> {
    let text = format!(
        "language junco.facts.v1; package benchmark; schema {};
        policy workload ordered {{ {mode} obligation on {{ {head} }}
        if {{ algebra {{ {} }}; }} report benchmark.rule; }}",
        schema.name(),
        tail.0
    );
    let mut rules = rules(&text, schema);
    assert_eq!(rules.len(), 1);
    rules.pop().unwrap()
}

pub struct LockSchema<P, R>(pub fn(u32) -> P, pub fn(u32) -> R);
impl<P, R> Schema<junco_policy::LockEvent<P, R>> for LockSchema<P, R>
where
    P: Copy + core::fmt::Debug + Eq + core::hash::Hash,
    R: Copy + core::fmt::Debug + Eq + core::hash::Hash,
{
    fn name(&self) -> &str {
        "lock"
    }
    fn field(&self, name: &str) -> Option<usize> {
        match name {
            "principal" => Some(0),
            "action" => Some(1),
            "resource" => Some(2),
            _ => None,
        }
    }
    fn constant(&self, name: &str) -> Option<junco_policy::LockComponent<P, R>> {
        use junco_policy::{Action, LockComponent as C};
        Some(match name {
            "action.read" => C::Action(Action::Read),
            "action.edit" => C::Action(Action::Edit),
            "action.release" => C::Action(Action::Release),
            "action.remove" => C::Action(Action::Remove),
            _ => {
                let (field, value) = name.split_once('.')?;
                let number = value.strip_prefix('v')?.parse::<u32>().ok()?;
                match field {
                    "principal" => C::Principal((self.0)(number)),
                    "resource" => C::Resource((self.1)(number)),
                    _ => return None,
                }
            }
        })
    }
    fn diagnostic(&self, name: &str) -> bool {
        matches!(
            name,
            "benchmark.rule" | "lock.owner" | "lock.stale" | "lock.reader"
        )
    }
}

pub const LOCKS: &str = include_str!("locks.facts");

pub fn lock_sources<P, R>(
    schema: &LockSchema<P, R>,
) -> Vec<(
    Rule<junco_policy::LockEvent<P, R>>,
    junco_policy::LockDiagnostic,
)>
where
    P: Copy + core::fmt::Debug + Eq + core::hash::Hash,
    R: Copy + core::fmt::Debug + Eq + core::hash::Hash,
{
    let module = parse(LOCKS, Limits::default()).expect("lock Facts source parses");
    lower(&module, schema, Limits::default())
        .expect("lock Facts source lowers")
        .obligations
        .into_iter()
        .map(|o| {
            let diagnostic = match o.metadata.report.as_str() {
                "lock.owner" => junco_policy::LockDiagnostic::Owner,
                "lock.stale" => junco_policy::LockDiagnostic::Stale,
                "lock.reader" => junco_policy::LockDiagnostic::Reader,
                _ => panic!("unknown lock diagnostic"),
            };
            (o.rule, diagnostic)
        })
        .collect()
}
