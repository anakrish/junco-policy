use crate::{Error, ErrorKind as K, Limits, Span};
use alloc::{boxed::Box, vec::Vec};
use history_syntax::RuleMode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Name<'s> {
    pub text: &'s str,
    pub span: Span,
}

#[derive(Debug)]
pub(crate) struct Expr<'s> {
    pub span: Span,
    pub kind: ExprKind<'s>,
}

#[derive(Debug)]
pub(crate) enum ExprKind<'s> {
    Bool(bool),
    EmptyHistory,
    Compare(Name<'s>, bool, Name<'s>),
    Call(Name<'s>, Vec<Name<'s>>),
    And(Vec<Expr<'s>>),
    Or(Vec<Expr<'s>>),
    Complement(Box<Expr<'s>>),
    Exists(Name<'s>, Box<Expr<'s>>),
    Since(Name<'s>, Box<Expr<'s>>, Box<Expr<'s>>),
    Algebra(Vec<AlgebraOp<'s>>),
}

#[derive(Debug)]
pub(crate) enum AlgebraOp<'s> {
    All(Span),
    Empty(Span),
    Epsilon(Span),
    Event(Name<'s>, Expr<'s>),
    Combine(Name<'s>, usize),
    Unary(Name<'s>),
}

#[derive(Debug)]
pub(crate) struct Definition<'s> {
    pub name: Name<'s>,
    pub event: bool,
    pub params: Vec<(Name<'s>, Name<'s>)>,
    pub body: Expr<'s>,
}

#[derive(Debug)]
pub(crate) struct SourceRule<'s> {
    pub policy: Name<'s>,
    pub name: Name<'s>,
    pub mode: RuleMode,
    pub head: Vec<(Name<'s>, Name<'s>)>,
    pub body: Expr<'s>,
    pub report: Name<'s>,
    pub span: Span,
}

/// Parsed module borrowing its bounded original source.
///
/// Constructed only by [`parse`]. Header names are inspectable; private syntax
/// must pass typed [`crate::lower`] before becoming executable source rules.
#[derive(Debug)]
pub struct Module<'s> {
    pub(crate) package: &'s str,
    pub(crate) schema: &'s str,
    pub(crate) schema_span: Span,
    pub(crate) declarations: usize,
    pub(crate) facts: Vec<(Name<'s>, Name<'s>, Name<'s>)>,
    pub(crate) defs: Vec<Definition<'s>>,
    pub(crate) rules: Vec<SourceRule<'s>>,
}

impl<'s> Module<'s> {
    /// Declared package name.
    pub fn package(&self) -> &'s str {
        self.package
    }
    /// Declared host schema name.
    pub fn schema(&self) -> &'s str {
        self.schema
    }
}

fn identifier(text: &str) -> bool {
    let mut bytes = text.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn reserved(text: &str) -> bool {
    matches!(
        text,
        "language"
            | "package"
            | "schema"
            | "fact"
            | "predicate"
            | "history"
            | "policy"
            | "ordered"
            | "require"
            | "forbid"
            | "on"
            | "if"
            | "report"
            | "event"
            | "exists"
            | "in"
            | "since"
            | "unless"
            | "complement"
            | "true"
            | "false"
            | "empty_history"
            | "and"
            | "or"
            | "not"
            | "_"
            | "algebra"
    )
}

/// Parse one module with byte, token, identifier, node, declaration and depth bounds.
///
/// Identifiers are ASCII, `#` starts a line comment, and qualified vocabulary names
/// are the only literal form. Unsupported constructs and trailing input are errors.
pub fn parse(source: &str, limits: Limits) -> Result<Module<'_>, Error> {
    if source.len() > limits.source_bytes {
        return Err(Error::new(
            K::Limit,
            Span {
                start: 0,
                end: source.len(),
            },
            "source byte limit",
        ));
    }
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes[pos].is_ascii_whitespace() {
            pos += 1;
            continue;
        }
        if bytes[pos] == b'#' {
            while pos < bytes.len() && bytes[pos] != b'\n' {
                pos += 1;
            }
            continue;
        }
        let start = pos;
        if bytes[pos].is_ascii_alphabetic() || bytes[pos] == b'_' {
            pos += 1;
            while pos < bytes.len()
                && (bytes[pos].is_ascii_alphanumeric() || matches!(bytes[pos], b'_' | b'.'))
            {
                pos += 1;
            }
            if pos - start > limits.lexeme_bytes {
                return Err(Error::new(
                    K::Limit,
                    Span { start, end: pos },
                    "identifier byte limit",
                ));
            }
            let count = source[start..pos]
                .strip_prefix("count.")
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
            if !count && !source[start..pos].split('.').all(identifier) {
                return Err(Error::new(
                    K::Syntax,
                    Span { start, end: pos },
                    "malformed qualified name",
                ));
            }
        } else if pos + 1 < bytes.len() && matches!(&bytes[pos..pos + 2], b"==" | b"!=" | b":=") {
            pos += 2;
        } else if matches!(bytes[pos], b'{' | b'}' | b'(' | b')' | b',' | b';' | b':') {
            pos += 1;
        } else {
            let end = pos
                + source[pos..]
                    .chars()
                    .next()
                    .expect("nonempty source")
                    .len_utf8();
            return Err(Error::new(
                K::Syntax,
                Span { start, end },
                "unsupported token; equality is comparison-only",
            ));
        }
        if tokens.len() >= limits.tokens {
            return Err(Error::new(
                K::Limit,
                Span { start, end: pos },
                "token limit",
            ));
        }
        tokens.push(Name {
            text: &source[start..pos],
            span: Span { start, end: pos },
        });
    }
    Parser {
        tokens,
        pos: 0,
        end: source.len(),
        limits,
        nodes: 0,
    }
    .module()
}

struct Parser<'s> {
    tokens: Vec<Name<'s>>,
    pos: usize,
    end: usize,
    limits: Limits,
    nodes: usize,
}

impl<'s> Parser<'s> {
    fn peek(&self) -> Name<'s> {
        self.tokens.get(self.pos).copied().unwrap_or(Name {
            text: "",
            span: Span {
                start: self.end,
                end: self.end,
            },
        })
    }
    fn take(&mut self) -> Result<Name<'s>, Error> {
        let token = self.peek();
        if token.text.is_empty() {
            return Err(Error::new(
                K::Syntax,
                token.span,
                "unexpected end of source",
            ));
        }
        self.pos += 1;
        Ok(token)
    }
    fn eat(&mut self, text: &str) -> bool {
        if self.peek().text == text {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn expect(&mut self, text: &str) -> Result<Name<'s>, Error> {
        if self.peek().text != text {
            return Err(Error::new(K::Syntax, self.peek().span, "unexpected token"));
        }
        self.take()
    }
    fn name(&mut self, qualified: bool) -> Result<Name<'s>, Error> {
        let name = self.take()?;
        if !name.text.split('.').all(identifier)
            || (!qualified && name.text.contains('.'))
            || reserved(name.text)
        {
            return Err(Error::new(
                K::Syntax,
                name.span,
                "expected nonreserved name",
            ));
        }
        Ok(name)
    }
    fn term(&mut self) -> Result<Name<'s>, Error> {
        if self.peek().text == "_" {
            self.take()
        } else {
            self.name(true)
        }
    }
    fn node(&mut self, depth: usize, span: Span) -> Result<(), Error> {
        if depth > self.limits.depth.min(64) || self.nodes >= self.limits.nodes {
            return Err(Error::new(K::Limit, span, "syntax depth/node limit"));
        }
        self.nodes += 1;
        Ok(())
    }
    fn unique(names: &mut Vec<&'s str>, name: Name<'s>) -> Result<(), Error> {
        if names.contains(&name.text) {
            return Err(Error::new(K::Duplicate, name.span, "duplicate declaration"));
        }
        names.push(name.text);
        Ok(())
    }
    fn module(mut self) -> Result<Module<'s>, Error> {
        self.expect("language")?;
        self.expect("junco.facts.v1")?;
        self.expect(";")?;
        self.expect("package")?;
        let package = self.name(true)?;
        self.expect(";")?;
        self.expect("schema")?;
        let schema = self.name(true)?;
        self.expect(";")?;
        let mut module = Module {
            package: package.text,
            schema: schema.text,
            schema_span: schema.span,
            declarations: 0,
            facts: Vec::new(),
            defs: Vec::new(),
            rules: Vec::new(),
        };
        let mut names = Vec::new();
        let mut policy_names = Vec::new();
        let mut declarations = 0;
        while !self.peek().text.is_empty() {
            if declarations >= self.limits.definitions {
                return Err(Error::new(K::Limit, self.peek().span, "declaration limit"));
            }
            declarations += 1;
            let kind = self.take()?;
            let name = self.name(false)?;
            match kind.text {
                "fact" => {
                    Self::unique(&mut names, name)?;
                    self.expect(":")?;
                    let field = self.name(false)?;
                    self.expect(":=")?;
                    let constant = self.name(true)?;
                    self.expect(";")?;
                    module.facts.push((name, field, constant));
                }
                "predicate" | "history" => {
                    Self::unique(&mut names, name)?;
                    self.expect("(")?;
                    let mut params = Vec::new();
                    let mut param_names = Vec::new();
                    if !self.eat(")") {
                        loop {
                            let param = self.name(false)?;
                            Self::unique(&mut param_names, param)?;
                            self.expect(":")?;
                            let ty = if self.peek().text == "event" {
                                self.take()?
                            } else {
                                self.name(false)?
                            };
                            params.push((param, ty));
                            if self.eat(")") {
                                break;
                            }
                            self.expect(",")?;
                        }
                    }
                    let event = kind.text == "predicate";
                    if (event && params.first().is_none_or(|p| p.1.text != "event"))
                        || params
                            .iter()
                            .skip(usize::from(event))
                            .any(|p| p.1.text == "event")
                    {
                        return Err(Error::new(
                            K::Type,
                            name.span,
                            "predicate requires one first event input; history requires only value inputs",
                        ));
                    }
                    self.expect("if")?;
                    let body = self.body(1)?;
                    module.defs.push(Definition {
                        name,
                        event,
                        params,
                        body,
                    });
                }
                "policy" => {
                    Self::unique(&mut policy_names, name)?;
                    self.expect("ordered")?;
                    self.expect("{")?;
                    let mut rule_names = Vec::new();
                    while !self.eat("}") {
                        if module.rules.len() >= self.limits.rules {
                            return Err(Error::new(K::Limit, self.peek().span, "obligation limit"));
                        }
                        let mode = self.take()?;
                        let mode_value = match mode.text {
                            "require" => RuleMode::Require,
                            "forbid" => RuleMode::Forbid,
                            _ => {
                                return Err(Error::new(
                                    K::Syntax,
                                    mode.span,
                                    "expected require or forbid",
                                ));
                            }
                        };
                        let rule_name = self.name(false)?;
                        Self::unique(&mut rule_names, rule_name)?;
                        self.expect("on")?;
                        self.expect("{")?;
                        let mut head = Vec::new();
                        let mut fields = Vec::new();
                        if !self.eat("}") {
                            loop {
                                let field = self.name(false)?;
                                Self::unique(&mut fields, field)?;
                                self.expect(":")?;
                                let value = self.term()?;
                                head.push((field, value));
                                if self.eat("}") {
                                    break;
                                }
                                self.expect(",")?;
                            }
                        }
                        self.expect("if")?;
                        let body = self.body(1)?;
                        self.expect("report")?;
                        let report = self.name(true)?;
                        let end = self.expect(";")?.span.end;
                        module.rules.push(SourceRule {
                            policy: name,
                            name: rule_name,
                            mode: mode_value,
                            head,
                            body,
                            report,
                            span: Span {
                                start: mode.span.start,
                                end,
                            },
                        });
                    }
                }
                _ => return Err(Error::new(K::Syntax, kind.span, "unsupported declaration")),
            }
        }
        module.declarations = declarations;
        Ok(module)
    }
    fn body(&mut self, depth: usize) -> Result<Expr<'s>, Error> {
        let start = self.expect("{")?.span.start;
        self.node(depth, self.peek().span)?;
        let mut clauses = Vec::new();
        while self.peek().text != "}" {
            clauses.push(self.expr(depth + 1, false)?);
            self.expect(";")?;
        }
        let end = self.expect("}")?.span.end;
        Ok(Expr {
            span: Span { start, end },
            kind: ExprKind::And(clauses),
        })
    }
    fn expr(&mut self, depth: usize, and: bool) -> Result<Expr<'s>, Error> {
        self.node(depth, self.peek().span)?;
        let first = if and {
            self.primary(depth + 1)?
        } else {
            self.expr(depth + 1, true)?
        };
        let op = if and { "and" } else { "or" };
        if self.peek().text != op {
            return Ok(first);
        }
        let start = first.span.start;
        let mut children = alloc::vec![first];
        while self.eat(op) {
            children.push(if and {
                self.primary(depth + 1)?
            } else {
                self.expr(depth + 1, true)?
            });
        }
        let end = children.last().expect("first expression").span.end;
        Ok(Expr {
            span: Span { start, end },
            kind: if and {
                ExprKind::And(children)
            } else {
                ExprKind::Or(children)
            },
        })
    }
    fn primary(&mut self, depth: usize) -> Result<Expr<'s>, Error> {
        let token = self.peek();
        self.node(depth, token.span)?;
        let kind = match token.text {
            "(" => {
                self.take()?;
                let inner = self.expr(depth + 1, false)?;
                self.expect(")")?;
                return Ok(inner);
            }
            "true" | "false" => {
                self.take()?;
                ExprKind::Bool(token.text == "true")
            }
            "empty_history" => {
                self.take()?;
                ExprKind::EmptyHistory
            }
            "complement" => {
                self.take()?;
                ExprKind::Complement(Box::new(self.primary(depth + 1)?))
            }
            "exists" | "since" => {
                self.take()?;
                let binder = self.name(false)?;
                self.expect("in")?;
                self.expect("history")?;
                let setter = Box::new(self.body(depth + 1)?);
                if token.text == "exists" {
                    ExprKind::Exists(binder, setter)
                } else {
                    self.expect("unless")?;
                    ExprKind::Since(binder, setter, Box::new(self.body(depth + 1)?))
                }
            }
            "algebra" => {
                self.take()?;
                self.expect("{")?;
                let mut ops = Vec::new();
                while !self.eat("}") {
                    let op = self.take()?;
                    self.node(depth, op.span)?;
                    let instruction = match op.text {
                        "all" => AlgebraOp::All(op.span),
                        "empty" => AlgebraOp::Empty(op.span),
                        "epsilon" => AlgebraOp::Epsilon(op.span),
                        "event" => {
                            let binder = self.name(false)?;
                            AlgebraOp::Event(binder, self.body(depth + 1)?)
                        }
                        "concat" | "union" | "intersect" => {
                            let count = self.take()?;
                            let number = count
                                .text
                                .strip_prefix("count.")
                                .and_then(|s| s.parse::<usize>().ok())
                                .ok_or_else(|| {
                                    Error::new(K::Syntax, count.span, "expected bounded count.N")
                                })?;
                            AlgebraOp::Combine(op, number)
                        }
                        "star" | "complement" => AlgebraOp::Unary(op),
                        _ => {
                            return Err(Error::new(
                                K::Syntax,
                                op.span,
                                "unsupported algebra instruction",
                            ));
                        }
                    };
                    self.expect(";")?;
                    ops.push(instruction);
                }
                ExprKind::Algebra(ops)
            }
            _ => {
                let name = self.name(true)?;
                if self.eat("(") {
                    let mut args = Vec::new();
                    if !self.eat(")") {
                        loop {
                            args.push(self.name(true)?);
                            if self.eat(")") {
                                break;
                            }
                            self.expect(",")?;
                        }
                    }
                    ExprKind::Call(name, args)
                } else {
                    let op = self.take()?;
                    if !matches!(op.text, "==" | "!=") {
                        return Err(Error::new(
                            K::Syntax,
                            op.span,
                            "expected comparison or static definition call",
                        ));
                    }
                    ExprKind::Compare(name, op.text == "==", self.name(true)?)
                }
            }
        };
        let end = self.tokens[self.pos - 1].span.end;
        Ok(Expr {
            span: Span {
                start: token.span.start,
                end,
            },
            kind,
        })
    }
}
