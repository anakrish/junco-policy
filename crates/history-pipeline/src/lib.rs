//! Bounded KQL-inspired pipelines lowering to the existing Junco typed syntax.
//!
//! This parser and host vocabulary are **not** covered by the evaluator's Verus
//! proofs. See the crate README for the grammar, limits and trust boundary.
//! Parsing requires only `alloc`; `runtime` adds compilation through `TracePolicy`.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod parser;

use alloc::{string::String, vec::Vec};
use core::fmt;
use history_syntax::{Component, Event, Rule};

/// Half-open UTF-8 byte offsets into the original source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// Structured parse/type/resource failure category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Syntax,
    UnknownName,
    Schema,
    Literal,
    Kind,
    Variable,
    Head,
    Duplicate,
    Unsupported,
    Limit,
}

/// A frontend failure, never an access decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub span: Span,
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} at {}..{}: {}",
            self.kind, self.span.start, self.span.end, self.message
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// The four expression kinds; none denotes a table or evaluator state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Selector,
    Predicate,
    Language,
    Rule,
}

/// A literal decoded according to the host's coordinate vocabulary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Literal {
    String(String),
    Integer(u64),
}

/// Static denial metadata, resolved during parsing rather than executed as source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub message: String,
    pub fixes: Vec<String>,
}

/// One host-registered event schema and tagged constant/diagnostic vocabulary.
///
/// `fields` must contain exactly `E::Arity::value()` unique ASCII names in
/// coordinate order. Decoded constants are checked with `E::coordinate`.
/// Unknown constants and diagnostic identifiers must return `None`.
pub trait Vocabulary<E: Event> {
    /// Case-sensitive identity asserted by the source schema declaration.
    fn schema(&self) -> &str;
    /// Coordinate names in the existing event's projection order.
    fn fields(&self) -> &[&str];
    /// Decode an accepted literal into a correctly tagged coordinate value.
    fn constant(&self, field: Component, literal: &Literal) -> Option<E::Component>;
    /// Resolve a bounded static diagnostic registration; unknown names return `None`.
    fn diagnostic(&self, _name: &str) -> Option<Diagnostic> {
        None
    }
}

/// Limits enforced before source-dependent allocation or static expansion.
///
/// These may be reduced, but not raised above the hard caps (see README).
/// `nodes` is a conservative cumulative construction/expansion budget, not
/// merely the final tree size. `nesting` bounds both parser and generated trees.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub source_bytes: usize,
    pub tokens: usize,
    pub literal_bytes: usize,
    pub nesting: usize,
    pub nodes: usize,
    pub rules: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            source_bytes: 65_536,
            tokens: 8_192,
            literal_bytes: 1_024,
            nesting: 32,
            nodes: 16_384,
            rules: 128,
        }
    }
}

/// An ordered source rule and its non-executable diagnostic sidecar.
#[derive(Clone, Debug)]
pub struct NamedRule<E: Event> {
    pub name: String,
    pub span: Span,
    pub rule: Rule<E>,
    pub diagnostic: Diagnostic,
}

/// A schema-checked, statically expanded document. Construction is private.
#[derive(Debug)]
pub struct Document<E: Event> {
    rules: Vec<NamedRule<E>>,
}

impl<E: Event> Document<E> {
    /// Inspect the existing typed DSL produced by parsing.
    pub fn rules(&self) -> &[NamedRule<E>] {
        &self.rules
    }
}

/// Parse, typecheck and hygienically expand a bounded source document.
///
/// Earlier definitions only; parameters cannot capture free candidate names.
/// Source length is rejected before lexing or allocation.
pub fn parse<E: Event>(
    source: &str,
    vocabulary: &impl Vocabulary<E>,
    limits: Limits,
) -> Result<Document<E>, Error> {
    parser::parse(source, vocabulary, limits)
}

/// Release the ordered typed rules without copying or numeric lowering.
pub fn lower<E: Event>(document: Document<E>) -> Vec<NamedRule<E>> {
    document.rules
}

/// Compile the document with the existing retained policy implementation.
///
/// Compile errors are returned unchanged. Use `TracePolicy::decide` on the
/// committed history; it never appends the candidate.
#[cfg(feature = "runtime")]
pub fn compile<E: Event + 'static>(
    document: Document<E>,
    store: alloc::sync::Arc<history_store::Store<E>>,
) -> Result<history_semantics::TracePolicy<E>, junco_core::CompileError> {
    let rules = lower(document).into_iter().map(|item| {
        let Diagnostic { message, fixes } = item.diagnostic;
        history_semantics::TraceRule::new(item.rule, move |_| (message.clone(), fixes.clone()))
    });
    history_semantics::TracePolicy::new(store, rules)
}
