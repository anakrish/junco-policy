use crate::parser::{AlgebraOp, Expr, ExprKind as X, Module, Name};
use crate::{Error, ErrorKind as K, Limits, Lowered, Metadata, Obligation, Schema, Span};
use alloc::{boxed::Box, format, string::ToString, vec, vec::Vec};
use history_syntax::{
    Arity, AtomPattern, Comparison, Component, ComponentPattern as P, Event, Head, RegexExpr as R,
    Rule, TestExpr as T,
};

#[derive(Clone)]
struct Value<E: Event> {
    coordinate: usize,
    pattern: P<E::Component>,
}
type Env<'s, E> = Vec<(&'s str, Value<E>)>;

/// Resolve and hygienically expand every definition, then lower all policy blocks
/// in textual order to existing typed rules.
///
/// Even unused definitions are checked. Facts must use qualified host vocabulary;
/// calls can refer forward, but cannot recurse or capture caller locals. The same
/// budget covers validation work and all expansions, not only the final output.
pub fn lower<E: Event>(
    module: &Module<'_>,
    schema: &impl Schema<E>,
    limits: Limits,
) -> Result<Lowered<E>, Error> {
    let mut resolver = Resolver {
        module,
        schema,
        limits,
        work: 0,
        facts: Vec::new(),
        stack: Vec::new(),
    };
    if module.schema != schema.name() {
        return Err(resolver.error(K::Unknown, module.schema_span, "unknown schema"));
    }
    if module.declarations > limits.definitions || module.rules.len() > limits.rules {
        return Err(resolver.error(K::Limit, module.schema_span, "declaration/obligation limit"));
    }
    for &(name, ty, constant) in &module.facts {
        resolver.tick(name.span, 1)?;
        let coordinate = resolver.field(ty)?;
        if !constant.text.contains('.') {
            return Err(resolver.error(
                K::Syntax,
                constant.span,
                "fact requires qualified host vocabulary, not an alias",
            ));
        }
        let value = resolver.constant(constant)?;
        resolver.same_coordinate(&value, coordinate, constant.span)?;
        resolver.facts.push((name.text, value));
    }
    for (index, def) in module.defs.iter().enumerate() {
        let mut env = Vec::new();
        let mut binder = None;
        for &(name, ty) in &def.params {
            resolver.tick(name.span, 1)?;
            resolver.safe_local(name)?;
            if ty.text == "event" {
                binder = Some(name.text);
            } else {
                env.push((
                    name.text,
                    Value {
                        coordinate: resolver.field(ty)?,
                        pattern: P::variable(format!("@validation.{}", name.text)),
                    },
                ));
            }
        }
        resolver.stack.push((index, def.name.span));
        let result = if def.event {
            resolver.event(&def.body, &env, binder, 1).map(|_| ())
        } else {
            resolver.history(&def.body, &env, 1).map(|tail| {
                Rule::new(history_syntax::RuleMode::Require, Head::new([]), tail).dispose();
            })
        };
        resolver.stack.pop();
        result?;
    }
    let mut obligations = Vec::new();
    for source in &module.rules {
        resolver.tick(source.span, 1)?;
        if !schema.diagnostic(source.report.text) {
            return Err(resolver.error(
                K::Unknown,
                source.report.span,
                "unregistered diagnostic identity",
            ));
        }
        let mut env = Vec::new();
        let arity = E::Arity::value();
        let mut slots: Vec<_> = (0..arity)
            .map(|i| P::variable(format!("@wild.{i}")))
            .collect();
        let mut seen = vec![false; arity];
        for &(field, term) in &source.head {
            resolver.tick(field.span, 1)?;
            let coordinate = resolver.field(field)?;
            if seen[coordinate] {
                return Err(resolver.error(K::Duplicate, field.span, "duplicate head coordinate"));
            }
            seen[coordinate] = true;
            if term.text == "_" {
                continue;
            }
            if term.text.contains('.') || resolver.facts.iter().any(|f| f.0 == term.text) {
                let value = resolver.value(term, &Vec::new())?;
                resolver.same_coordinate(&value, coordinate, term.span)?;
                slots[coordinate] = value.pattern;
            } else {
                resolver.safe_local(term)?;
                if env.iter().any(|(name, _)| *name == term.text) {
                    return Err(resolver.error(
                        K::Type,
                        term.span,
                        "candidate variable cannot bind two coordinates",
                    ));
                }
                let pattern = P::variable(format!("@candidate.{coordinate}"));
                env.push((
                    term.text,
                    Value {
                        coordinate,
                        pattern: pattern.clone(),
                    },
                ));
                slots[coordinate] = pattern;
            }
        }
        let tail = resolver.history(&source.body, &env, 1)?;
        obligations.push(Obligation {
            rule: Rule::new(source.mode, Head::new(slots), tail),
            metadata: Metadata {
                ordinal: obligations.len(),
                name: format!(
                    "{}.{}.{}",
                    module.package, source.policy.text, source.name.text
                ),
                report: source.report.text.to_string(),
                span: source.span,
            },
        });
    }
    Ok(Lowered {
        package: module.package.to_string(),
        schema: module.schema.to_string(),
        obligations,
    })
}

struct Resolver<'m, 's, E: Event, S> {
    module: &'m Module<'s>,
    schema: &'m S,
    limits: Limits,
    work: usize,
    facts: Vec<(&'s str, Value<E>)>,
    stack: Vec<(usize, Span)>,
}

impl<'s, E: Event, S: Schema<E>> Resolver<'_, 's, E, S> {
    fn error(&self, kind: K, span: Span, message: &'static str) -> Error {
        Error {
            kind,
            span,
            message,
            expansion: self.stack.iter().map(|p| p.1).collect(),
        }
    }
    fn tick(&mut self, span: Span, depth: usize) -> Result<(), Error> {
        if depth > self.limits.depth.min(64) || self.work >= self.limits.expansion {
            return Err(self.error(K::Limit, span, "expansion work/depth limit"));
        }
        self.work += 1;
        Ok(())
    }
    fn field(&self, name: Name<'_>) -> Result<usize, Error> {
        let coordinate = self
            .schema
            .field(name.text)
            .ok_or_else(|| self.error(K::Unknown, name.span, "unknown field/type"))?;
        if coordinate >= E::Arity::value() {
            return Err(self.error(
                K::Type,
                name.span,
                "host field coordinate outside event arity",
            ));
        }
        Ok(coordinate)
    }
    fn constant(&self, name: Name<'_>) -> Result<Value<E>, Error> {
        let value = self
            .schema
            .constant(name.text)
            .ok_or_else(|| self.error(K::Unknown, name.span, "unknown vocabulary constant"))?;
        let coordinate = E::coordinate(value);
        if coordinate >= E::Arity::value() {
            return Err(self.error(K::Type, name.span, "host constant tag outside event arity"));
        }
        Ok(Value {
            coordinate,
            pattern: P::Constant(value),
        })
    }
    fn value(&self, name: Name<'_>, env: &Env<'s, E>) -> Result<Value<E>, Error> {
        if let Some((_, value)) = env.iter().find(|p| p.0 == name.text) {
            return Ok(value.clone());
        }
        if let Some((_, value)) = self.facts.iter().find(|p| p.0 == name.text) {
            return Ok(value.clone());
        }
        if name.text.contains('.') {
            return self.constant(name);
        }
        Err(self.error(
            K::Scope,
            name.span,
            "unbound value; comparisons do not introduce variables",
        ))
    }
    fn same_coordinate(
        &self,
        value: &Value<E>,
        coordinate: usize,
        span: Span,
    ) -> Result<(), Error> {
        if value.coordinate != coordinate {
            return Err(self.error(K::Type, span, "value belongs to a different coordinate"));
        }
        Ok(())
    }
    fn safe_local(&self, name: Name<'_>) -> Result<(), Error> {
        if self.module.facts.iter().any(|f| f.0.text == name.text)
            || self.module.defs.iter().any(|d| d.name.text == name.text)
        {
            return Err(self.error(
                K::Duplicate,
                name.span,
                "local name collides with a fact/definition",
            ));
        }
        Ok(())
    }
    fn binder(&self, name: Name<'s>, env: &Env<'s, E>) -> Result<(), Error> {
        self.safe_local(name)?;
        if env.iter().any(|p| p.0 == name.text) {
            return Err(self.error(
                K::Scope,
                name.span,
                "event binder collides with value input",
            ));
        }
        Ok(())
    }
    fn call(
        &mut self,
        name: Name<'s>,
        args: &[Name<'s>],
        env: &Env<'s, E>,
        binder: Option<&'s str>,
        event: bool,
        depth: usize,
    ) -> Result<(usize, Env<'s, E>), Error> {
        self.tick(name.span, depth)?;
        let index = self
            .module
            .defs
            .iter()
            .position(|d| d.name.text == name.text)
            .ok_or_else(|| {
                self.error(
                    K::Unknown,
                    name.span,
                    "unknown static definition; imports and arbitrary calls unsupported",
                )
            })?;
        let def = &self.module.defs[index];
        if self.stack.iter().any(|p| p.0 == index) {
            return Err(self.error(K::Cycle, name.span, "cyclic static definitions"));
        }
        if def.event != event || args.len() != def.params.len() {
            return Err(self.error(
                K::Type,
                name.span,
                "wrong definition sort or argument count",
            ));
        }
        let mut inputs = Vec::new();
        for (i, (&arg, &(param, ty))) in args.iter().zip(&def.params).enumerate() {
            self.tick(arg.span, depth)?;
            if event && i == 0 {
                if binder != Some(arg.text) {
                    return Err(self.error(
                        K::Scope,
                        arg.span,
                        "predicate first argument must be the current event binder",
                    ));
                }
            } else {
                let value = self.value(arg, env)?;
                self.same_coordinate(&value, self.field(ty)?, arg.span)?;
                inputs.push((param.text, value));
            }
        }
        Ok((index, inputs))
    }
    fn event(
        &mut self,
        expr: &Expr<'s>,
        env: &Env<'s, E>,
        binder: Option<&'s str>,
        depth: usize,
    ) -> Result<T<E>, Error> {
        self.tick(expr.span, depth)?;
        Ok(match &expr.kind {
            X::Bool(true) => T::True,
            X::Bool(false) => T::False,
            X::Compare(left, equal, right) => {
                let (event, field) = left.text.split_once('.').ok_or_else(|| {
                    self.error(
                        K::Syntax,
                        left.span,
                        "comparison left side must be event.field",
                    )
                })?;
                if binder != Some(event) {
                    return Err(self.error(K::Scope, left.span, "event binder is not in scope"));
                }
                let coordinate = self.field(Name {
                    text: field,
                    span: left.span,
                })?;
                let value = self.value(*right, env)?;
                self.same_coordinate(&value, coordinate, right.span)?;
                T::atom(
                    if *equal {
                        Comparison::Eq
                    } else {
                        Comparison::Neq
                    },
                    AtomPattern::new(Component::new(coordinate), value.pattern),
                )
            }
            X::And(xs) | X::Or(xs) => {
                let children = xs
                    .iter()
                    .map(|x| self.event(x, env, binder, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?;
                if matches!(expr.kind, X::And(_)) {
                    T::And(children)
                } else {
                    T::Or(children)
                }
            }
            X::Call(name, args) => {
                let (index, inputs) = self.call(*name, args, env, binder, true, depth + 1)?;
                let def = &self.module.defs[index];
                self.stack.push((index, name.span));
                let result = self.event(&def.body, &inputs, Some(def.params[0].0.text), depth + 1);
                self.stack.pop();
                result?
            }
            _ => {
                return Err(self.error(
                    K::Type,
                    expr.span,
                    "history expression is not a one-event predicate",
                ));
            }
        })
    }
    fn history(&mut self, expr: &Expr<'s>, env: &Env<'s, E>, depth: usize) -> Result<R<E>, Error> {
        self.tick(expr.span, depth)?;
        Ok(match &expr.kind {
            X::Bool(true) => R::All,
            X::Bool(false) => R::Empty,
            X::EmptyHistory => R::Epsilon,
            X::And(xs) | X::Or(xs) => {
                let children = xs
                    .iter()
                    .map(|x| self.history(x, env, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?;
                if matches!(expr.kind, X::And(_)) {
                    R::Intersect(children)
                } else {
                    R::Union(children)
                }
            }
            X::Complement(x) => R::Not(Box::new(self.history(x, env, depth + 1)?)),
            X::Call(name, args) => {
                let (index, inputs) = self.call(*name, args, env, None, false, depth + 1)?;
                let def = &self.module.defs[index];
                self.stack.push((index, name.span));
                let result = self.history(&def.body, &inputs, depth + 1);
                self.stack.pop();
                result?
            }
            X::Exists(binder, setter) => {
                self.binder(*binder, env)?;
                let test = self.event(setter, env, Some(binder.text), depth + 1)?;
                for _ in 0..3 {
                    self.tick(expr.span, depth)?;
                }
                R::Concat(vec![R::All, R::Test(test), R::All])
            }
            X::Since(binder, setter, clear) => {
                self.binder(*binder, env)?;
                let setter = self.event(setter, env, Some(binder.text), depth + 1)?;
                let clear = self.event(clear, env, Some(binder.text), depth + 1)?;
                let stable = self.negate(clear, expr.span, depth + 1)?;
                for _ in 0..4 {
                    self.tick(expr.span, depth)?;
                }
                R::Concat(vec![
                    R::All,
                    R::Test(setter),
                    R::Star(Box::new(R::Test(stable))),
                ])
            }
            X::Algebra(ops) => self.algebra(ops, env, depth + 1, expr.span)?,
            _ => {
                return Err(self.error(
                    K::Type,
                    expr.span,
                    "one-event comparison requires exists/since or a predicate definition",
                ));
            }
        })
    }
    fn algebra(
        &mut self,
        ops: &[AlgebraOp<'s>],
        env: &Env<'s, E>,
        depth: usize,
        span: Span,
    ) -> Result<R<E>, Error> {
        let mut stack: Vec<(R<E>, usize)> = Vec::new();
        let result = (|| {
            for op in ops {
                self.tick(span, depth)?;
                match op {
                    AlgebraOp::All(s) | AlgebraOp::Empty(s) | AlgebraOp::Epsilon(s) => {
                        self.tick(*s, depth)?;
                        let regex = match op {
                            AlgebraOp::All(_) => R::All,
                            AlgebraOp::Empty(_) => R::Empty,
                            _ => R::Epsilon,
                        };
                        stack.push((regex, 1));
                    }
                    AlgebraOp::Event(binder, body) => {
                        self.binder(*binder, env)?;
                        stack.push((
                            R::Test(self.event(body, env, Some(binder.text), depth + 1)?),
                            1,
                        ));
                    }
                    AlgebraOp::Combine(name, count) => {
                        if *count > stack.len() {
                            return Err(self.error(K::Type, name.span, "algebra stack underflow"));
                        }
                        let begin = stack.len() - count;
                        let height = stack[begin..].iter().map(|p| p.1).max().unwrap_or(0) + 1;
                        if height > 256 {
                            return Err(self.error(
                                K::Limit,
                                name.span,
                                "algebra tree depth limit (256)",
                            ));
                        }
                        let children = stack.drain(begin..).map(|p| p.0).collect();
                        let regex = match name.text {
                            "concat" => R::Concat(children),
                            "union" => R::Union(children),
                            _ => R::Intersect(children),
                        };
                        stack.push((regex, height));
                    }
                    AlgebraOp::Unary(name) => {
                        let height = stack
                            .last()
                            .ok_or_else(|| {
                                self.error(K::Type, name.span, "algebra stack underflow")
                            })?
                            .1
                            + 1;
                        if height > 256 {
                            return Err(self.error(
                                K::Limit,
                                name.span,
                                "algebra tree depth limit (256)",
                            ));
                        }
                        let (regex, _) = stack.pop().expect("checked nonempty stack");
                        stack.push((
                            if name.text == "star" {
                                R::Star(Box::new(regex))
                            } else {
                                R::Not(Box::new(regex))
                            },
                            height,
                        ));
                    }
                }
            }
            if stack.len() != 1 {
                return Err(self.error(
                    K::Type,
                    span,
                    "algebra must produce exactly one complete-history language",
                ));
            }
            Ok(stack.pop().expect("one algebra result").0)
        })();
        for (tail, _) in stack {
            Rule::new(history_syntax::RuleMode::Require, Head::new([]), tail).dispose();
        }
        result
    }
    fn negate(&mut self, test: T<E>, span: Span, depth: usize) -> Result<T<E>, Error> {
        self.tick(span, depth)?;
        Ok(match test {
            T::True => T::False,
            T::False => T::True,
            T::Atom {
                comparison,
                pattern,
            } => T::Atom {
                comparison: !comparison,
                pattern,
            },
            T::And(xs) => T::Or(
                xs.into_iter()
                    .map(|x| self.negate(x, span, depth + 1))
                    .collect::<Result<_, _>>()?,
            ),
            T::Or(xs) => T::And(
                xs.into_iter()
                    .map(|x| self.negate(x, span, depth + 1))
                    .collect::<Result<_, _>>()?,
            ),
        })
    }
}
