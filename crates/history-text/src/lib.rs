#![no_std]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod parser;
mod resolve;

pub use parser::{ParsedPolicy, parse, parse_bytes};
pub use resolve::{Entry, LowerError, RuleInfo, TypedPolicy, lower};

use alloc::{string::String, vec::Vec};
use core::fmt;
use history_syntax::{Component, Event};

/// Caller-assigned source identity, unrelated to engine identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceId(pub u32);

/// Half-open UTF-8 byte range. Missing tokens use zero-width ranges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub source: SourceId,
    pub start: usize,
    pub end: usize,
}

impl Span {
    /// Derives one-based line and Unicode-scalar column; CRLF is one newline.
    /// Returns `None` for a different source or an invalid byte boundary.
    pub fn location(self, source: Source<'_>) -> Option<(usize, usize)> {
        if self.source != source.id || self.start > self.end {
            return None;
        }
        source.text.get(self.start..self.end)?;
        let mut line = 1;
        let mut column = 1;
        let mut cr = false;
        for c in source.text[..self.start].chars() {
            match c {
                '\r' => {
                    line += 1;
                    column = 1;
                }
                '\n' if cr => {}
                '\n' => {
                    line += 1;
                    column = 1;
                }
                _ => column += 1,
            }
            cr = c == '\r';
        }
        Some((line, column))
    }
}

/// Borrowed source; its identity is retained in diagnostics and provenance.
#[derive(Clone, Copy, Debug)]
pub struct Source<'a> {
    pub id: SourceId,
    pub text: &'a str,
}

/// Stable fail-fast diagnostic categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    InvalidUtf8,
    InvalidToken,
    InvalidString,
    InvalidInteger,
    UnexpectedToken,
    Unsupported,
    Version,
    Schema,
    UnknownCoordinate,
    UnknownAlias,
    DuplicateName,
    Head,
    UnboundVariable,
    WrongCoordinate,
    InvalidLiteral,
    Adapter,
    Limit,
    Allocation,
}

/// Allocation-free frontend error. `related` identifies an earlier declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: Code,
    pub span: Span,
    pub related: Option<Span>,
    pub message: &'static str,
}

impl Diagnostic {
    pub(crate) fn new(code: Code, span: Span, message: &'static str) -> Self {
        Self {
            code,
            span,
            related: None,
            message,
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} at {}:{}..{}: {}",
            self.code, self.span.source.0, self.span.start, self.span.end, self.message
        )
    }
}
impl core::error::Error for Diagnostic {}

/// Frontend ceilings. Values may only lower the defaults (the absolute ceilings).
/// Bounds cover the entire document; there is no static expression expansion.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub source_bytes: usize,
    pub tokens: usize,
    pub identifier_bytes: usize,
    pub literal_bytes: usize,
    pub nesting: usize,
    pub nodes: usize,
    pub rules: usize,
    pub constants: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            source_bytes: 1 << 20,
            tokens: 65_536,
            identifier_bytes: 128,
            literal_bytes: 4096,
            nesting: 64,
            nodes: 32_768,
            rules: 256,
            constants: 1024,
        }
    }
}

impl Limits {
    pub(crate) fn validate(self, span: Span) -> Result<(), Diagnostic> {
        let max = Self::default();
        if self.source_bytes > max.source_bytes
            || self.tokens > max.tokens
            || self.identifier_bytes > max.identifier_bytes
            || self.literal_bytes > max.literal_bytes
            || self.nesting > max.nesting
            || self.nodes > max.nodes
            || self.rules > max.rules
            || self.constants > max.constants
        {
            return Err(Diagnostic::new(
                Code::Limit,
                span,
                "limits exceed absolute ceilings",
            ));
        }
        Ok(())
    }
}

/// Literal forms accepted by a coordinate; no conversion between forms is implied.
#[derive(Clone, Copy, Debug)]
pub struct LiteralKinds {
    pub string: bool,
    pub integer: bool,
    pub boolean: bool,
}

/// Host coordinate declaration, in native event coordinate order.
#[derive(Clone, Copy, Debug)]
pub struct CoordinateSpec<'a> {
    pub name: &'a str,
    pub domain: &'a str,
    pub literals: LiteralKinds,
}

/// Exact host schema identifier and ordered coordinate declarations.
#[derive(Clone, Copy, Debug)]
pub struct Vocabulary<'a> {
    pub id: &'a str,
    pub coordinates: &'a [CoordinateSpec<'a>],
}

/// A checked lexical value. Integer spelling is exact and arbitrary precision;
/// the host must reject values outside its domain, rather than truncate them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Literal<'a> {
    Symbol(&'a str),
    String(&'a str),
    Integer(&'a str),
    Boolean(bool),
}

/// Immutable host name registry. Every returned tag is checked by the frontend.
/// Host errors (including operational registry errors) retain their original type.
pub trait Resolver<E: Event> {
    type Error;
    fn vocabulary(&self) -> Vocabulary<'_>;
    fn resolve(
        &self,
        coordinate: Component,
        literal: Literal<'_>,
    ) -> Result<E::Component, Self::Error>;
}

pub(crate) fn push<T>(values: &mut Vec<T>, value: T, span: Span) -> Result<(), Diagnostic> {
    values
        .try_reserve(1)
        .map_err(|_| Diagnostic::new(Code::Allocation, span, "allocation failed"))?;
    values.push(value);
    Ok(())
}

pub(crate) fn owned(value: &str, span: Span) -> Result<String, Diagnostic> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| Diagnostic::new(Code::Allocation, span, "allocation failed"))?;
    result.push_str(value);
    Ok(result)
}

/// Host-controlled denial renderer; text contains no executable diagnostics.
#[cfg(feature = "runtime")]
pub type DenialRenderer<E> =
    alloc::sync::Arc<dyn Fn(&RuleInfo, &E) -> (String, Vec<String>) + Send + Sync>;

/// Engine compilation failure, honestly associated with the document, not an
/// inferred rule index (the existing constructor drains its input on failure).
#[cfg(feature = "runtime")]
#[derive(Debug)]
pub struct TextCompileError {
    pub span: Span,
    pub error: junco_core::CompileError,
}

#[cfg(feature = "runtime")]
impl fmt::Display for TextCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
#[cfg(feature = "runtime")]
impl core::error::Error for TextCompileError {}

/// Compiles once through the existing public API. `TracePolicy::decide` never
/// appends the candidate and returns operational history errors unchanged.
#[cfg(feature = "runtime")]
pub fn compile<E: Event + 'static>(
    policy: TypedPolicy<E>,
    store: alloc::sync::Arc<history_store::Store<E>>,
    render: DenialRenderer<E>,
) -> Result<history_semantics::TracePolicy<E>, TextCompileError> {
    let span = policy.span;
    let rules = policy.into_entries().map(|entry| {
        let render = render.clone();
        history_semantics::TraceRule::new(entry.rule, move |candidate| {
            render(&entry.info, candidate)
        })
    });
    history_semantics::TracePolicy::new(store, rules)
        .map_err(|error| TextCompileError { span, error })
}
