//! Shared benchmark-only text loaders. Parsing/lowering precede engine timers.
use history_syntax::{Component, Event, Rule};
use history_text::{
    CoordinateSpec, Limits, Literal, LiteralKinds, Resolver, Source, SourceId, Vocabulary,
};
use junco_policy::{Action, LockComponent, LockEvent};
use std::fmt::Debug;
use std::hash::Hash;

pub const IDS: LiteralKinds = LiteralKinds {
    string: false,
    integer: true,
    boolean: false,
};
pub const SYMBOLS: LiteralKinds = LiteralKinds {
    string: false,
    integer: false,
    boolean: false,
};
pub const LOCK_COORDINATES: [CoordinateSpec<'static>; 3] = [
    CoordinateSpec {
        name: "principal",
        domain: "actor",
        literals: IDS,
    },
    CoordinateSpec {
        name: "action",
        domain: "lock-action",
        literals: SYMBOLS,
    },
    CoordinateSpec {
        name: "resource",
        domain: "path",
        literals: IDS,
    },
];

pub struct LockVocabulary<P, R> {
    pub principal: fn(u32) -> P,
    pub resource: fn(u32) -> R,
}

impl<P: Copy + Debug + Eq + Hash, R: Copy + Debug + Eq + Hash> Resolver<LockEvent<P, R>>
    for LockVocabulary<P, R>
{
    type Error = &'static str;
    fn vocabulary(&self) -> Vocabulary<'_> {
        Vocabulary {
            id: "bench.lock/1",
            coordinates: &LOCK_COORDINATES,
        }
    }
    fn resolve(
        &self,
        coordinate: Component,
        literal: Literal<'_>,
    ) -> Result<LockComponent<P, R>, Self::Error> {
        match (coordinate.index(), literal) {
            (0, Literal::Integer(s)) => Ok(LockComponent::Principal((self.principal)(
                s.parse().map_err(|_| "invalid actor id")?,
            ))),
            (2, Literal::Integer(s)) => Ok(LockComponent::Resource((self.resource)(
                s.parse().map_err(|_| "invalid path id")?,
            ))),
            (1, Literal::Symbol(s)) => Ok(LockComponent::Action(match s {
                "read" => Action::Read,
                "edit" => Action::Edit,
                "release" => Action::Release,
                "remove" => Action::Remove,
                _ => return Err("unknown action"),
            })),
            _ => Err("unsupported lock literal"),
        }
    }
}

pub fn load<E: Event, R: Resolver<E>>(text: &str, resolver: &R) -> Vec<Rule<E>>
where
    R::Error: Debug,
{
    let parsed = history_text::parse_generated(
        Source {
            id: SourceId(1),
            text,
        },
        Limits::generated(),
    )
    .expect("benchmark text parses");
    history_text::lower(&parsed, resolver)
        .expect("benchmark vocabulary resolves")
        .into_entries()
        .map(|entry| entry.rule)
        .collect()
}

pub fn lock_rule<P: Copy + Debug + Eq + Hash, R: Copy + Debug + Eq + Hash>(
    text: &str,
    principal: fn(u32) -> P,
    resource: fn(u32) -> R,
) -> Rule<LockEvent<P, R>> {
    let mut rules = load(
        text,
        &LockVocabulary {
            principal,
            resource,
        },
    );
    assert_eq!(rules.len(), 1);
    rules.pop().unwrap()
}

pub fn lock_document(name: &str, mode: &str, action: &str, tail: &str) -> String {
    format!("junco 1; schema \"bench.lock/1\"; policy benchmark {{
        rule {name} {{ candidate {{ principal: $actor, action: action.{action}, resource: $target }};
        {mode} {tail}; }} }}")
}

/// Text algebra for generated workloads: never constructs or serializes a DSL tree.
pub fn concat(parts: impl IntoIterator<Item = String>) -> String {
    chain(parts, " >> ", "epsilon")
}
pub fn union(parts: impl IntoIterator<Item = String>) -> String {
    chain(parts, " | ", "empty")
}
pub fn intersect(parts: impl IntoIterator<Item = String>) -> String {
    chain(parts, " & ", "all")
}
fn chain(parts: impl IntoIterator<Item = String>, op: &str, identity: &str) -> String {
    let parts = parts.into_iter().collect::<Vec<_>>();
    if parts.is_empty() {
        identity.to_owned()
    } else {
        format!("({})", parts.join(op))
    }
}
pub fn star(part: String) -> String {
    format!("({part})*")
}
pub fn complement(part: String) -> String {
    format!("!({part})")
}
pub fn contains(part: String) -> String {
    concat(["all".into(), part, "all".into()])
}

pub const LOCK_POLICY: &str = include_str!("lock.junco");

/// Owned generated Junco Text expression, with no native DSL value behind it.
#[derive(Clone)]
pub struct Expression(pub String);
impl Expression {
    pub fn all() -> Self {
        Self("all".into())
    }
    pub fn empty() -> Self {
        Self("empty".into())
    }
    pub fn epsilon() -> Self {
        Self("epsilon".into())
    }
    pub fn concat(parts: impl IntoIterator<Item = Self>) -> Self {
        Self(concat(parts.into_iter().map(|p| p.0)))
    }
    pub fn union(parts: impl IntoIterator<Item = Self>) -> Self {
        Self(union(parts.into_iter().map(|p| p.0)))
    }
    pub fn intersect(parts: impl IntoIterator<Item = Self>) -> Self {
        Self(intersect(parts.into_iter().map(|p| p.0)))
    }
    pub fn star(part: Self) -> Self {
        Self(star(part.0))
    }
    pub fn complement(part: Self) -> Self {
        Self(complement(part.0))
    }
}
