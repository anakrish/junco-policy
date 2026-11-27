use crate::parser::{Expr, Name, Op, Value, identifier, reserved};
use crate::{Code, Diagnostic, Literal, ParsedPolicy, Resolver, Span, Vocabulary, owned, push};
use alloc::{string::String, vec::Vec};
use core::fmt;
use history_syntax::{
    Arity, AtomPattern, Comparison, Component, ComponentPattern, Event, Head, RegexExpr, Rule,
    TestExpr,
};
use junco_core::scope::VariableScope;

/// Typed lowering failure. Resolver errors are not converted into syntax errors
/// or false predicates; the original error and literal source span are retained.
#[derive(Debug)]
pub enum LowerError<T> {
    Frontend(Diagnostic),
    Resolver { span: Span, error: T },
}
impl<T> From<Diagnostic> for LowerError<T> {
    fn from(error: Diagnostic) -> Self {
        Self::Frontend(error)
    }
}
impl<T: fmt::Display> fmt::Display for LowerError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frontend(error) => error.fmt(f),
            Self::Resolver { span, error } => write!(
                f,
                "resolver at {}:{}..{}: {}",
                span.source.0, span.start, span.end, error
            ),
        }
    }
}
impl<T: core::error::Error + 'static> core::error::Error for LowerError<T> {}

/// Source metadata, independent of DSL meaning. `origins` contains head fields
/// and syntax nodes in traversal order (including atoms and operator ranges).
#[derive(Clone, Debug)]
pub struct RuleInfo {
    pub name: String,
    pub span: Span,
    pub head_span: Span,
    pub origins: Vec<Span>,
}

/// One ordered rule and its provenance.
#[derive(Debug)]
pub struct Entry<E: Event> {
    pub rule: Rule<E>,
    pub info: RuleInfo,
}

/// Owned, schema-checked DSL rules, with no store, numeric encoding or evaluator.
#[derive(Debug)]
pub struct TypedPolicy<E: Event> {
    pub name: String,
    pub span: Span,
    entries: Vec<Entry<E>>,
}
impl<E: Event> TypedPolicy<E> {
    /// Rules in source order; a satisfied rule is not an early grant.
    pub fn entries(&self) -> &[Entry<E>] {
        &self.entries
    }
    /// Consume into existing compiler/validator integrations.
    pub fn into_entries(self) -> alloc::vec::IntoIter<Entry<E>> {
        self.entries.into_iter()
    }
}

struct Alias<'a, C> {
    name: Name<'a>,
    coordinate: Component,
    value: C,
}

/// Resolves names and tags without normalization or expression expansion.
/// All rules are checked, including heads that might not match a later candidate.
pub fn lower<E: Event, R: Resolver<E>>(
    parsed: &ParsedPolicy<'_>,
    resolver: &R,
) -> Result<TypedPolicy<E>, LowerError<R::Error>> {
    let vocabulary = resolver.vocabulary();
    let arity = E::Arity::value();
    if vocabulary.id != parsed.schema {
        return Err(Diagnostic::new(
            Code::Schema,
            parsed.span,
            "schema identifier does not match host vocabulary",
        )
        .into());
    }
    if vocabulary.coordinates.len() != arity {
        return Err(Diagnostic::new(
            Code::Adapter,
            parsed.span,
            "host coordinate count does not match native event arity",
        )
        .into());
    }
    for (i, spec) in vocabulary.coordinates.iter().enumerate() {
        if !identifier(spec.name)
            || reserved(spec.name)
            || spec.domain.is_empty()
            || vocabulary.coordinates[..i]
                .iter()
                .any(|other| other.name == spec.name)
        {
            return Err(Diagnostic::new(
                Code::Adapter,
                parsed.span,
                "invalid or duplicate host coordinate declaration",
            )
            .into());
        }
    }
    let mut aliases = Vec::new();
    for constant in &parsed.constants {
        let coordinate = coordinate(vocabulary, constant.coordinate)?;
        let value =
            constant_value::<E, R>(&constant.value, coordinate, vocabulary, resolver, &aliases)?;
        push(
            &mut aliases,
            Alias {
                name: constant.name,
                coordinate,
                value,
            },
            constant.name.span,
        )?;
    }
    let mut entries = Vec::new();
    for rule in &parsed.rules {
        if rule.fields.len() != arity {
            return Err(Diagnostic::new(
                Code::Head,
                rule.head_span,
                "candidate must name every coordinate exactly once",
            )
            .into());
        }
        let mut slots: [Option<ComponentPattern<E::Component>>; 8] = core::array::from_fn(|_| None);
        let mut bindings: [Option<Name<'_>>; 8] = [None; 8];
        let mut scope = VariableScope::new(arity);
        let mut origins = Vec::new();
        for field in &rule.fields {
            let coordinate = coordinate(vocabulary, field.coordinate)?;
            let pattern = match &field.value {
                Value::Variable(name) => {
                    if let Some(previous) =
                        bindings.iter().flatten().find(|old| old.text == name.text)
                    {
                        let mut error = Diagnostic::new(
                            Code::WrongCoordinate,
                            name.span,
                            "variable may bind only one coordinate",
                        );
                        error.related = Some(previous.span);
                        return Err(error.into());
                    }
                    scope.bind(coordinate, name.text).map_err(|_| {
                        Diagnostic::new(
                            Code::WrongCoordinate,
                            name.span,
                            "conflicting head variable",
                        )
                    })?;
                    bindings[coordinate.index()] = Some(*name);
                    ComponentPattern::Variable(owned(name.text, name.span)?)
                }
                value => ComponentPattern::Constant(constant_value::<E, R>(
                    value, coordinate, vocabulary, resolver, &aliases,
                )?),
            };
            slots[coordinate.index()] = Some(pattern);
            push(
                &mut origins,
                Span {
                    end: field.value.span().end,
                    ..field.coordinate.span
                },
                field.coordinate.span,
            )?;
        }
        let mut head = Vec::new();
        for slot in slots.into_iter().take(arity) {
            push(
                &mut head,
                slot.ok_or_else(|| {
                    Diagnostic::new(Code::Head, rule.head_span, "missing candidate coordinate")
                })?,
                rule.head_span,
            )?;
        }
        let context = Context::<E, R> {
            parsed,
            vocabulary,
            resolver,
            aliases: &aliases,
            scope: &scope,
            bindings: &bindings,
        };
        let tail = context.regex(rule.tail, &mut origins)?;
        push(
            &mut entries,
            Entry {
                rule: Rule::new(rule.mode, Head::new(head), tail),
                info: RuleInfo {
                    name: owned(rule.name.text, rule.name.span)?,
                    span: rule.span,
                    head_span: rule.head_span,
                    origins,
                },
            },
            rule.span,
        )?;
    }
    Ok(TypedPolicy {
        name: owned(parsed.name, parsed.span)?,
        span: parsed.span,
        entries,
    })
}

fn coordinate(vocabulary: Vocabulary<'_>, name: Name<'_>) -> Result<Component, Diagnostic> {
    vocabulary
        .coordinates
        .iter()
        .position(|spec| spec.name == name.text)
        .map(Component::new)
        .ok_or_else(|| Diagnostic::new(Code::UnknownCoordinate, name.span, "unknown coordinate"))
}

fn constant_value<E: Event, R: Resolver<E>>(
    value: &Value<'_>,
    expected: Component,
    vocabulary: Vocabulary<'_>,
    resolver: &R,
    aliases: &[Alias<'_, E::Component>],
) -> Result<E::Component, LowerError<R::Error>> {
    let span = value.span();
    let kinds = vocabulary.coordinates[expected.index()].literals;
    let literal = match value {
        Value::Symbol(name, symbol) => {
            if coordinate(vocabulary, *name)? != expected {
                return Err(Diagnostic::new(
                    Code::WrongCoordinate,
                    span,
                    "qualified symbol belongs to another coordinate",
                )
                .into());
            }
            Literal::Symbol(symbol.text)
        }
        Value::String(text, _) if kinds.string => Literal::String(text),
        Value::Integer(name) if kinds.integer => Literal::Integer(name.text),
        Value::Boolean(value, _) if kinds.boolean => Literal::Boolean(*value),
        Value::Alias(name) => {
            let alias = aliases
                .iter()
                .find(|alias| alias.name.text == name.text)
                .ok_or_else(|| {
                    Diagnostic::new(Code::UnknownAlias, name.span, "unknown constant alias")
                })?;
            if alias.coordinate != expected {
                let mut error = Diagnostic::new(
                    Code::WrongCoordinate,
                    span,
                    "alias belongs to another coordinate",
                );
                error.related = Some(alias.name.span);
                return Err(error.into());
            }
            return Ok(alias.value);
        }
        _ => {
            return Err(Diagnostic::new(
                Code::InvalidLiteral,
                span,
                "literal form is not supported by this coordinate",
            )
            .into());
        }
    };
    let component = resolver
        .resolve(expected, literal)
        .map_err(|error| LowerError::Resolver { span, error })?;
    if E::coordinate(component) != expected.index() {
        return Err(Diagnostic::new(
            Code::Adapter,
            span,
            "resolver returned a wrongly tagged component",
        )
        .into());
    }
    Ok(component)
}

struct Context<'a, 's, E: Event, R: Resolver<E>> {
    parsed: &'a ParsedPolicy<'s>,
    vocabulary: Vocabulary<'a>,
    resolver: &'a R,
    aliases: &'a [Alias<'s, E::Component>],
    scope: &'a VariableScope<'s>,
    bindings: &'a [Option<Name<'s>>; 8],
}
impl<E: Event, R: Resolver<E>> Context<'_, '_, E, R> {
    fn pattern(
        &self,
        value: &Value<'_>,
        expected: Component,
    ) -> Result<ComponentPattern<E::Component>, LowerError<R::Error>> {
        if let Value::Variable(name) = value {
            // Inspect borrowed scope first, avoiding the core helper's allocating
            // error paths while retaining its coordinate-local success check.
            if self.scope.name(expected) != Some(name.text) {
                let previous = self
                    .bindings
                    .iter()
                    .flatten()
                    .find(|bound| bound.text == name.text);
                let mut error = Diagnostic::new(
                    if previous.is_some() {
                        Code::WrongCoordinate
                    } else {
                        Code::UnboundVariable
                    },
                    name.span,
                    "variable must be bound in this rule at this coordinate",
                );
                error.related = previous.map(|bound| bound.span);
                return Err(error.into());
            }
            self.scope.resolve(expected, name.text).map_err(|_| {
                Diagnostic::new(Code::Adapter, name.span, "inconsistent variable scope")
            })?;
            Ok(ComponentPattern::Variable(owned(name.text, name.span)?))
        } else {
            Ok(ComponentPattern::Constant(constant_value::<E, R>(
                value,
                expected,
                self.vocabulary,
                self.resolver,
                self.aliases,
            )?))
        }
    }
    fn regex(
        &self,
        id: usize,
        origins: &mut Vec<Span>,
    ) -> Result<RegexExpr<E>, LowerError<R::Error>> {
        let node = &self.parsed.nodes[id];
        push(origins, node.span, node.span)?;
        Ok(match &node.expr {
            Expr::All => RegexExpr::All,
            Expr::Empty => RegexExpr::Empty,
            Expr::Epsilon => RegexExpr::Epsilon,
            Expr::Event(child) => RegexExpr::Test(self.test(*child, origins)?),
            Expr::Unary(op, child) => {
                let child = self.regex(*child, origins)?;
                match op {
                    Op::Star => RegexExpr::star(child),
                    Op::Not => RegexExpr::complement(child),
                    _ => {
                        return Err(Diagnostic::new(
                            Code::Adapter,
                            node.span,
                            "invalid internal history operator",
                        )
                        .into());
                    }
                }
            }
            Expr::List(op, children) => {
                let mut values = Vec::new();
                for &child in children {
                    push(&mut values, self.regex(child, origins)?, node.span)?;
                }
                match op {
                    Op::Union => RegexExpr::Union(values),
                    Op::Intersect => RegexExpr::Intersect(values),
                    Op::Concat => RegexExpr::Concat(values),
                    _ => {
                        return Err(Diagnostic::new(
                            Code::Adapter,
                            node.span,
                            "invalid internal history list",
                        )
                        .into());
                    }
                }
            }
            _ => {
                return Err(Diagnostic::new(
                    Code::Adapter,
                    node.span,
                    "predicate used as history internally",
                )
                .into());
            }
        })
    }
    fn test(
        &self,
        id: usize,
        origins: &mut Vec<Span>,
    ) -> Result<TestExpr<E>, LowerError<R::Error>> {
        let node = &self.parsed.nodes[id];
        push(origins, node.span, node.span)?;
        Ok(match &node.expr {
            Expr::True => TestExpr::True,
            Expr::False => TestExpr::False,
            Expr::Atom(name, equal, value) => {
                let coordinate = coordinate(self.vocabulary, *name)?;
                TestExpr::atom(
                    if *equal {
                        Comparison::Eq
                    } else {
                        Comparison::Neq
                    },
                    AtomPattern::new(coordinate, self.pattern(value, coordinate)?),
                )
            }
            Expr::List(op, children) => {
                let mut values = Vec::new();
                for &child in children {
                    push(&mut values, self.test(child, origins)?, node.span)?;
                }
                match op {
                    Op::And => TestExpr::And(values),
                    Op::Or => TestExpr::Or(values),
                    _ => {
                        return Err(Diagnostic::new(
                            Code::Adapter,
                            node.span,
                            "invalid internal predicate operator",
                        )
                        .into());
                    }
                }
            }
            _ => {
                return Err(Diagnostic::new(
                    Code::Adapter,
                    node.span,
                    "history used as predicate internally",
                )
                .into());
            }
        })
    }
}
