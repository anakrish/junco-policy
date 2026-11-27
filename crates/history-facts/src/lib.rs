//! Rego-inspired (not Rego-compatible), bounded static facts over committed histories.
//!
//! [`parse`] borrows text; [`lower`] resolves a host [`Schema`] and produces the existing
//! typed DSL. Neither evaluates text. With `runtime`, `Lowered::compile` delegates
//! compilation and noncommitting decisions to `history_semantics::TracePolicy`.
//! The parser, schema adapter and lowering are not covered by the core's Verus proofs.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod lower;
mod parser;

use alloc::{string::String, vec::Vec};
use core::fmt;
use history_syntax::{Event, Rule};
pub use lower::lower;
pub use parser::{Module, parse};

/// Half-open UTF-8 byte offsets into the original source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Span {
    /// Inclusive start.
    pub start: usize,
    /// Exclusive end.
    pub end: usize,
}

/// Stable frontend error classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Invalid or unsupported syntax.
    Syntax,
    /// Unknown vocabulary, field, definition, schema or diagnostic.
    Unknown,
    /// A name is declared twice or ambiguously.
    Duplicate,
    /// Expression sort, argument count or coordinate mismatch.
    Type,
    /// A variable or event reference is not in scope.
    Scope,
    /// Recursive static definitions.
    Cycle,
    /// A frontend resource budget was exhausted.
    Limit,
}

/// A source error, never a false history fact or an authorization result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// Error category.
    pub kind: ErrorKind,
    /// The failing token, expression or declaration.
    pub span: Span,
    /// Human-readable explanation.
    pub message: &'static str,
    /// Definition call sites, outermost first; empty for parsing errors.
    pub expansion: Vec<Span>,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, span: Span, message: &'static str) -> Self {
        Self {
            kind,
            span,
            message,
            expansion: Vec::new(),
        }
    }
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
impl core::error::Error for Error {}

/// Frontend budgets. Source size is checked before allocating tokens or syntax.
///
/// Depth has an additional hard ceiling of 64 to bound recursive parsing,
/// expansion, Boolean negation and destruction even with permissive host settings.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Source bytes.
    pub source_bytes: usize,
    /// Lexed tokens.
    pub tokens: usize,
    /// Bytes per identifier/vocabulary token (no strings in v1).
    pub lexeme_bytes: usize,
    /// Syntax and expansion nesting, at most 64.
    pub depth: usize,
    /// Parsed expression nodes.
    pub nodes: usize,
    /// Total facts, predicates, histories and policy blocks.
    pub definitions: usize,
    /// Total obligations.
    pub rules: usize,
    /// Expansion work and produced DSL nodes, including validation of unused definitions.
    pub expansion: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            source_bytes: 1024 * 1024,
            tokens: 100_000,
            lexeme_bytes: 4096,
            depth: 64,
            nodes: 100_000,
            definitions: 1024,
            rules: 1024,
            expansion: 100_000,
        }
    }
}

/// Host-owned vocabulary for exactly one event type.
///
/// Fields resolve to coordinates, constants to *tagged* components. Lowering
/// checks tags and arity; the host still owes the existing `Event` laws.
/// These lookups must be deterministic and bounded. No arbitrary source calls
/// or implicit conversions are supported.
pub trait Schema<E: Event> {
    /// Name accepted by the module's schema header.
    fn name(&self) -> &str;
    /// Resolve a field/type name into a coordinate.
    fn field(&self, name: &str) -> Option<usize>;
    /// Resolve a qualified vocabulary name into a tagged value.
    fn constant(&self, name: &str) -> Option<E::Component>;
    /// Whether this diagnostic identity is registered.
    fn diagnostic(&self, name: &str) -> bool;
}

/// Diagnostic identity and source ordering, independent of callback implementations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    /// Zero-based ordinal across policy blocks in textual order.
    pub ordinal: usize,
    /// `package.policy.obligation`.
    pub name: String,
    /// Registered report key.
    pub report: String,
    /// Complete obligation span.
    pub span: Span,
}

/// One source obligation paired permanently with its metadata.
#[derive(Clone, Debug)]
pub struct Obligation<E: Event> {
    /// Existing owned typed source rule.
    pub rule: Rule<E>,
    /// Stable name, report identity and source position.
    pub metadata: Metadata,
}

/// Resolved, ordered source rules; contains no runtime evaluator or private lowering.
#[derive(Clone, Debug)]
pub struct Lowered<E: Event> {
    /// Module package.
    pub package: String,
    /// Selected host schema.
    pub schema: String,
    /// Textually ordered obligations.
    pub obligations: Vec<Obligation<E>>,
}

#[cfg(feature = "runtime")]
impl<E: Event + 'static> Lowered<E> {
    /// Pair source rules with host diagnostics, in source order.
    ///
    /// The factory is called once per obligation at assembly, not during evaluation.
    /// Metadata remains available to callers before consuming this object.
    pub fn into_trace_rules<F, D>(self, mut factory: F) -> Vec<history_semantics::TraceRule<E>>
    where
        F: FnMut(&Metadata) -> D,
        D: Fn(&E) -> (String, Vec<String>) + Send + Sync + 'static,
    {
        self.obligations
            .into_iter()
            .map(|item| {
                let diagnostic = factory(&item.metadata);
                history_semantics::TraceRule::new(item.rule, diagnostic)
            })
            .collect()
    }

    /// Compile using registered report identities as default denial text.
    ///
    /// No diagnostic callbacks are invented for a host; use [`Self::into_trace_rules`]
    /// for richer native diagnostics. Compile errors propagate unchanged, and the
    /// returned policy's `decide` returns operational errors without appending candidates.
    pub fn compile(
        self,
        store: alloc::sync::Arc<history_store::Store<E>>,
    ) -> Result<history_semantics::TracePolicy<E>, junco_core::CompileError> {
        history_semantics::TracePolicy::new(
            store,
            self.into_trace_rules(|meta| {
                let report = meta.report.clone();
                move |_: &E| (report.clone(), Vec::new())
            }),
        )
    }
}
