use crate::{Code, Diagnostic, Limits, Source, SourceId, Span, push};
use alloc::{string::String, vec::Vec};
use history_syntax::RuleMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Word,
    Variable,
    String,
    Integer,
    Symbol,
    Eof,
}
#[derive(Clone, Copy, Debug)]
struct Token<'a> {
    kind: Kind,
    text: &'a str,
    span: Span,
}

pub(crate) fn identifier(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
pub(crate) fn reserved(s: &str) -> bool {
    matches!(
        s,
        "junco"
            | "schema"
            | "policy"
            | "const"
            | "rule"
            | "candidate"
            | "require"
            | "forbid"
            | "all"
            | "empty"
            | "epsilon"
            | "event"
            | "and"
            | "or"
            | "true"
            | "false"
    )
}

/// Parsed, bounded syntax. Opaque fields prevent callers from bypassing checks.
/// No schema resolver is called until [`crate::lower`].
#[derive(Debug)]
pub struct ParsedPolicy<'a> {
    pub(crate) source: Source<'a>,
    pub(crate) schema: String,
    pub(crate) name: &'a str,
    pub(crate) span: Span,
    pub(crate) constants: Vec<Constant<'a>>,
    pub(crate) rules: Vec<ParsedRule<'a>>,
    pub(crate) nodes: Vec<Node<'a>>,
}
impl ParsedPolicy<'_> {
    /// Borrowed source used to render provenance and diagnostics.
    pub fn source(&self) -> Source<'_> {
        self.source
    }
    /// Whole document range.
    pub fn span(&self) -> Span {
        self.span
    }
    /// Policy identity, not a priority or runtime instruction.
    pub fn name(&self) -> &str {
        self.name
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Name<'a> {
    pub text: &'a str,
    pub span: Span,
}
#[derive(Debug)]
pub(crate) enum Value<'a> {
    Variable(Name<'a>),
    Alias(Name<'a>),
    Symbol(Name<'a>, Name<'a>),
    String(String, Span),
    Integer(Name<'a>),
    Boolean(bool, Span),
}
impl Value<'_> {
    pub(crate) fn span(&self) -> Span {
        match self {
            Self::Variable(n) | Self::Alias(n) | Self::Integer(n) => n.span,
            Self::Symbol(a, b) => Span {
                end: b.span.end,
                ..a.span
            },
            Self::String(_, s) | Self::Boolean(_, s) => *s,
        }
    }
}
#[derive(Debug)]
pub(crate) struct Constant<'a> {
    pub name: Name<'a>,
    pub coordinate: Name<'a>,
    pub value: Value<'a>,
}
#[derive(Debug)]
pub(crate) struct Field<'a> {
    pub coordinate: Name<'a>,
    pub value: Value<'a>,
}
#[derive(Debug)]
pub(crate) struct ParsedRule<'a> {
    pub name: Name<'a>,
    pub span: Span,
    pub head_span: Span,
    pub fields: Vec<Field<'a>>,
    pub mode: RuleMode,
    pub tail: usize,
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum Op {
    Union,
    Intersect,
    Concat,
    Star,
    Not,
    And,
    Or,
}
#[derive(Debug)]
pub(crate) enum Expr<'a> {
    All,
    Empty,
    Epsilon,
    True,
    False,
    Event(usize),
    Atom(Name<'a>, bool, Value<'a>),
    Unary(Op, usize),
    List(Op, Vec<usize>),
}
#[derive(Debug)]
pub(crate) struct Node<'a> {
    pub expr: Expr<'a>,
    pub span: Span,
    height: usize,
}

/// Checks byte limits and UTF-8 before any frontend allocation.
pub fn parse_bytes(
    id: SourceId,
    bytes: &[u8],
    limits: Limits,
) -> Result<ParsedPolicy<'_>, Diagnostic> {
    let span = Span {
        source: id,
        start: 0,
        end: 0,
    };
    limits.validate(span)?;
    if bytes.len() > limits.source_bytes {
        return Err(Diagnostic::new(
            Code::Limit,
            span,
            "source byte limit exceeded",
        ));
    }
    let text = core::str::from_utf8(bytes).map_err(|e| {
        Diagnostic::new(
            Code::InvalidUtf8,
            Span {
                start: e.valid_up_to(),
                end: e.valid_up_to(),
                ..span
            },
            "invalid UTF-8",
        )
    })?;
    parse(Source { id, text }, limits)
}

/// Parses the explicit v1 grammar, consuming the entire source.
pub fn parse(source: Source<'_>, limits: Limits) -> Result<ParsedPolicy<'_>, Diagnostic> {
    let span = Span {
        source: source.id,
        start: 0,
        end: 0,
    };
    limits.validate(span)?;
    if source.text.len() > limits.source_bytes {
        return Err(Diagnostic::new(
            Code::Limit,
            span,
            "source byte limit exceeded",
        ));
    }
    let tokens = lex(source, limits)?;
    Parser {
        source,
        limits,
        tokens,
        at: 0,
        nodes: Vec::new(),
    }
    .document()
}

fn lex(source: Source<'_>, limits: Limits) -> Result<Vec<Token<'_>>, Diagnostic> {
    let text = source.text;
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let start = at;
        let span = Span {
            source: source.id,
            start,
            end: start,
        };
        if matches!(bytes[at], b' ' | b'\t' | b'\r' | b'\n') {
            at += 1;
            continue;
        }
        if text[at..].starts_with("//") {
            while at < bytes.len() && !matches!(bytes[at], b'\r' | b'\n') {
                at += 1;
            }
            continue;
        }
        if tokens.len() >= limits.tokens {
            return Err(Diagnostic::new(Code::Limit, span, "token limit exceeded"));
        }
        let kind;
        match bytes[at] {
            b'a'..=b'z' | b'A'..=b'Z' | b'$' => {
                kind = if bytes[at] == b'$' {
                    at += 1;
                    Kind::Variable
                } else {
                    Kind::Word
                };
                let name_start = at;
                if at == bytes.len() || !bytes[at].is_ascii_alphabetic() {
                    return Err(Diagnostic::new(
                        Code::InvalidToken,
                        span,
                        "expected variable identifier",
                    ));
                }
                at += 1;
                while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                    at += 1;
                }
                if at - name_start > limits.identifier_bytes {
                    return Err(Diagnostic::new(
                        Code::Limit,
                        span,
                        "identifier byte limit exceeded",
                    ));
                }
            }
            b'"' => {
                kind = Kind::String;
                at += 1;
                let mut escaped = false;
                while at < bytes.len() {
                    let b = bytes[at];
                    at += 1;
                    if !escaped && b == b'"' {
                        break;
                    }
                    escaped = !escaped && b == b'\\';
                }
                if at - start > limits.literal_bytes {
                    return Err(Diagnostic::new(
                        Code::Limit,
                        span,
                        "raw literal byte limit exceeded",
                    ));
                }
                decode(
                    &text[start..at],
                    Span { end: at, ..span },
                    limits.literal_bytes,
                    false,
                )?;
            }
            b'-' | b'0'..=b'9' => {
                kind = Kind::Integer;
                if bytes[at] == b'-' {
                    at += 1;
                }
                let digits = at;
                while at < bytes.len() && bytes[at].is_ascii_digit() {
                    at += 1;
                }
                let value = &text[digits..at];
                if value.is_empty()
                    || (value.len() > 1 && value.starts_with('0'))
                    || (at < bytes.len()
                        && (bytes[at].is_ascii_alphanumeric() || matches!(bytes[at], b'.' | b'_')))
                {
                    return Err(Diagnostic::new(
                        Code::InvalidInteger,
                        Span { end: at, ..span },
                        "invalid decimal integer",
                    ));
                }
                if at - start > limits.literal_bytes {
                    return Err(Diagnostic::new(
                        Code::Limit,
                        span,
                        "literal byte limit exceeded",
                    ));
                }
            }
            _ => {
                kind = Kind::Symbol;
                if text[at..].starts_with(">>")
                    || text[at..].starts_with("==")
                    || text[at..].starts_with("!=")
                {
                    at += 2;
                } else if matches!(
                    bytes[at],
                    b';' | b'{'
                        | b'}'
                        | b':'
                        | b','
                        | b'='
                        | b'.'
                        | b'('
                        | b')'
                        | b'!'
                        | b'*'
                        | b'|'
                        | b'&'
                ) {
                    at += 1;
                } else {
                    let end = at + text[at..].chars().next().expect("nonempty").len_utf8();
                    return Err(Diagnostic::new(
                        Code::Unsupported,
                        Span { end, ..span },
                        "unsupported character or construct",
                    ));
                }
            }
        }
        push(
            &mut tokens,
            Token {
                kind,
                text: &text[start..at],
                span: Span { end: at, ..span },
            },
            span,
        )?;
    }
    let span = Span {
        source: source.id,
        start: at,
        end: at,
    };
    push(
        &mut tokens,
        Token {
            kind: Kind::Eof,
            text: "",
            span,
        },
        span,
    )?;
    Ok(tokens)
}

// Two passes: validate/count decoded bytes before allocating or decoding.
fn decode(raw: &str, span: Span, limit: usize, allocate: bool) -> Result<String, Diagnostic> {
    fn visit(
        raw: &str,
        span: Span,
        mut emit: impl FnMut(char) -> Result<(), Diagnostic>,
    ) -> Result<(), Diagnostic> {
        let fail = || {
            Diagnostic::new(
                Code::InvalidString,
                span,
                "invalid JSON string or surrogate escape",
            )
        };
        if raw.len() < 2 || !raw.ends_with('"') {
            return Err(fail());
        }
        let mut chars = raw[1..raw.len() - 1].chars();
        while let Some(c) = chars.next() {
            let decoded = match c {
                '"' | '\0'..='\x1f' => return Err(fail()),
                '\\' => match chars.next().ok_or_else(fail)? {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    'b' => '\x08',
                    'f' => '\x0c',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'u' => {
                        let mut hex = || -> Result<u32, Diagnostic> {
                            let mut n = 0;
                            for _ in 0..4 {
                                n = n * 16
                                    + chars.next().and_then(|c| c.to_digit(16)).ok_or_else(fail)?;
                            }
                            Ok(n)
                        };
                        let high = hex()?;
                        let scalar = if (0xd800..=0xdbff).contains(&high) {
                            if chars.next() != Some('\\') || chars.next() != Some('u') {
                                return Err(fail());
                            }
                            let mut low = 0;
                            for _ in 0..4 {
                                low = low * 16
                                    + chars.next().and_then(|c| c.to_digit(16)).ok_or_else(fail)?;
                            }
                            if !(0xdc00..=0xdfff).contains(&low) {
                                return Err(fail());
                            }
                            0x10000 + ((high - 0xd800) << 10) + low - 0xdc00
                        } else {
                            high
                        };
                        char::from_u32(scalar).ok_or_else(fail)?
                    }
                    _ => return Err(fail()),
                },
                _ => c,
            };
            emit(decoded)?;
        }
        Ok(())
    }
    let mut size = 0usize;
    visit(raw, span, |c| {
        size = size
            .checked_add(c.len_utf8())
            .ok_or_else(|| Diagnostic::new(Code::Limit, span, "literal size overflow"))?;
        if size > limit {
            return Err(Diagnostic::new(
                Code::Limit,
                span,
                "decoded literal byte limit exceeded",
            ));
        }
        Ok(())
    })?;
    let mut result = String::new();
    if allocate {
        result
            .try_reserve_exact(size)
            .map_err(|_| Diagnostic::new(Code::Allocation, span, "allocation failed"))?;
        visit(raw, span, |c| {
            result.push(c);
            Ok(())
        })?;
    }
    Ok(result)
}

struct Parser<'a> {
    source: Source<'a>,
    limits: Limits,
    tokens: Vec<Token<'a>>,
    at: usize,
    nodes: Vec<Node<'a>>,
}
impl<'a> Parser<'a> {
    fn peek(&self) -> Token<'a> {
        self.tokens[self.at]
    }
    fn take(&mut self) -> Token<'a> {
        let token = self.peek();
        if token.kind != Kind::Eof {
            self.at += 1;
        }
        token
    }
    fn eat(&mut self, text: &str) -> bool {
        if self.peek().text == text && self.peek().kind != Kind::Eof {
            self.take();
            true
        } else {
            false
        }
    }
    fn expect(&mut self, text: &'static str) -> Result<Token<'a>, Diagnostic> {
        if self.peek().text == text && self.peek().kind != Kind::Eof {
            Ok(self.take())
        } else {
            Err(Diagnostic::new(
                Code::UnexpectedToken,
                self.peek().span,
                text,
            ))
        }
    }
    fn name(&mut self) -> Result<Name<'a>, Diagnostic> {
        let token = self.peek();
        if token.kind != Kind::Word || reserved(token.text) {
            return Err(Diagnostic::new(
                Code::UnexpectedToken,
                token.span,
                "expected non-keyword identifier",
            ));
        }
        self.take();
        Ok(Name {
            text: token.text,
            span: token.span,
        })
    }
    fn string(&mut self) -> Result<String, Diagnostic> {
        let t = self.peek();
        if t.kind != Kind::String {
            return Err(Diagnostic::new(
                Code::UnexpectedToken,
                t.span,
                "expected string",
            ));
        }
        self.take();
        decode(t.text, t.span, self.limits.literal_bytes, true)
    }
    fn value(&mut self, aliases: bool, variables: bool) -> Result<Value<'a>, Diagnostic> {
        let t = self.peek();
        match t.kind {
            Kind::Variable if variables => {
                self.take();
                if reserved(&t.text[1..]) {
                    return Err(Diagnostic::new(
                        Code::UnexpectedToken,
                        t.span,
                        "keyword variable",
                    ));
                }
                Ok(Value::Variable(Name {
                    text: &t.text[1..],
                    span: t.span,
                }))
            }
            Kind::String => Ok(Value::String(self.string()?, t.span)),
            Kind::Integer => {
                self.take();
                Ok(Value::Integer(Name {
                    text: t.text,
                    span: t.span,
                }))
            }
            Kind::Word => {
                self.take();
                if self.eat(".") {
                    if reserved(t.text) {
                        return Err(Diagnostic::new(
                            Code::UnexpectedToken,
                            t.span,
                            "keyword coordinate",
                        ));
                    }
                    let symbol = self.peek();
                    if symbol.kind != Kind::Word {
                        return Err(Diagnostic::new(
                            Code::UnexpectedToken,
                            symbol.span,
                            "expected symbol",
                        ));
                    }
                    self.take();
                    Ok(Value::Symbol(
                        Name {
                            text: t.text,
                            span: t.span,
                        },
                        Name {
                            text: symbol.text,
                            span: symbol.span,
                        },
                    ))
                } else if matches!(t.text, "true" | "false") {
                    Ok(Value::Boolean(t.text == "true", t.span))
                } else if aliases && !reserved(t.text) {
                    Ok(Value::Alias(Name {
                        text: t.text,
                        span: t.span,
                    }))
                } else {
                    Err(Diagnostic::new(
                        Code::UnexpectedToken,
                        t.span,
                        "expected coordinate-qualified constant",
                    ))
                }
            }
            _ => Err(Diagnostic::new(
                Code::UnexpectedToken,
                t.span,
                "expected value",
            )),
        }
    }
    fn document(mut self) -> Result<ParsedPolicy<'a>, Diagnostic> {
        self.expect("junco")?;
        let version = self.take();
        if version.kind != Kind::Integer || version.text != "1" {
            return Err(Diagnostic::new(
                Code::Version,
                version.span,
                "only junco 1 is supported",
            ));
        }
        self.expect(";")?;
        self.expect("schema")?;
        let schema = self.string()?;
        self.expect(";")?;
        self.expect("policy")?;
        let name = self.name()?;
        self.expect("{")?;
        let mut constants: Vec<Constant<'a>> = Vec::new();
        while self.eat("const") {
            if constants.len() >= self.limits.constants {
                return Err(Diagnostic::new(
                    Code::Limit,
                    self.peek().span,
                    "constant limit exceeded",
                ));
            }
            let name = self.name()?;
            duplicate(constants.iter().map(|c| c.name), name)?;
            self.expect(":")?;
            let coordinate = self.name()?;
            self.expect("=")?;
            let value = self.value(false, false)?;
            self.expect(";")?;
            push(
                &mut constants,
                Constant {
                    name,
                    coordinate,
                    value,
                },
                name.span,
            )?;
        }
        let mut rules: Vec<ParsedRule<'a>> = Vec::new();
        while self.eat("rule") {
            if rules.len() >= self.limits.rules {
                return Err(Diagnostic::new(
                    Code::Limit,
                    self.peek().span,
                    "rule limit exceeded",
                ));
            }
            let name = self.name()?;
            duplicate(rules.iter().map(|r| r.name), name)?;
            self.expect("{")?;
            self.expect("candidate")?;
            let start = self.expect("{")?.span;
            let mut fields: Vec<Field<'a>> = Vec::new();
            loop {
                let coordinate = self.name()?;
                duplicate(fields.iter().map(|f| f.coordinate), coordinate)?;
                if fields.len() >= 8 {
                    return Err(Diagnostic::new(
                        Code::Head,
                        coordinate.span,
                        "at most eight coordinates",
                    ));
                }
                self.expect(":")?;
                let value = self.value(true, true)?;
                push(&mut fields, Field { coordinate, value }, coordinate.span)?;
                if !self.eat(",") || self.peek().text == "}" {
                    break;
                }
            }
            let end = self.expect("}")?.span.end;
            let head_span = Span { end, ..start };
            self.expect(";")?;
            let mode = if self.eat("require") {
                RuleMode::Require
            } else {
                self.expect("forbid")?;
                RuleMode::Forbid
            };
            let tail = self.history(0, 0)?;
            self.expect(";")?;
            let end = self.expect("}")?.span.end;
            push(
                &mut rules,
                ParsedRule {
                    name,
                    span: Span { end, ..name.span },
                    head_span,
                    fields,
                    mode,
                    tail,
                },
                name.span,
            )?;
        }
        self.expect("}")?;
        if self.peek().kind != Kind::Eof {
            return Err(Diagnostic::new(
                Code::UnexpectedToken,
                self.peek().span,
                "trailing input",
            ));
        }
        Ok(ParsedPolicy {
            source: self.source,
            schema,
            name: name.text,
            span: Span {
                source: self.source.id,
                start: 0,
                end: self.source.text.len(),
            },
            constants,
            rules,
            nodes: self.nodes,
        })
    }
    fn node(&mut self, expr: Expr<'a>, span: Span) -> Result<usize, Diagnostic> {
        if self.nodes.len() >= self.limits.nodes {
            return Err(Diagnostic::new(Code::Limit, span, "node limit exceeded"));
        }
        let height = 1 + match &expr {
            Expr::Event(child) | Expr::Unary(_, child) => self.nodes[*child].height,
            Expr::List(_, children) => children
                .iter()
                .map(|&i| self.nodes[i].height)
                .max()
                .unwrap_or(0),
            _ => 0,
        };
        if height > self.limits.nesting {
            return Err(Diagnostic::new(
                Code::Limit,
                span,
                "expression tree depth exceeded",
            ));
        }
        let id = self.nodes.len();
        push(&mut self.nodes, Node { expr, span, height }, span)?;
        Ok(id)
    }
    fn depth(&self, depth: usize) -> Result<(), Diagnostic> {
        if depth >= self.limits.nesting {
            Err(Diagnostic::new(
                Code::Limit,
                self.peek().span,
                "nesting limit exceeded",
            ))
        } else {
            Ok(())
        }
    }
    fn history(&mut self, level: usize, depth: usize) -> Result<usize, Diagnostic> {
        if level < 3 {
            let child = self.history(level + 1, depth)?;
            let (symbol, op) = [("|", Op::Union), ("&", Op::Intersect), (">>", Op::Concat)][level];
            if self.peek().text != symbol {
                return Ok(child);
            }
            let mut children = Vec::new();
            let start = self.nodes[child].span;
            push(&mut children, child, start)?;
            while self.eat(symbol) {
                let next = self.history(level + 1, depth)?;
                push(&mut children, next, self.nodes[next].span)?;
            }
            let end = self.nodes[*children.last().expect("nonempty")].span.end;
            return self.node(Expr::List(op, children), Span { end, ..start });
        }
        self.depth(depth)?;
        if self.eat("!") {
            let start = self.tokens[self.at - 1].span;
            let child = self.history(3, depth + 1)?;
            return self.node(
                Expr::Unary(Op::Not, child),
                Span {
                    end: self.nodes[child].span.end,
                    ..start
                },
            );
        }
        let t = self.take();
        let child = match t.text {
            "all" => self.node(Expr::All, t.span)?,
            "empty" => self.node(Expr::Empty, t.span)?,
            "epsilon" => self.node(Expr::Epsilon, t.span)?,
            "(" => {
                let child = self.history(0, depth + 1)?;
                self.expect(")")?;
                child
            }
            "event" => {
                self.expect("{")?;
                let test = self.predicate(0, depth + 1)?;
                let end = self.expect("}")?.span.end;
                self.node(Expr::Event(test), Span { end, ..t.span })?
            }
            _ => {
                return Err(Diagnostic::new(
                    Code::UnexpectedToken,
                    t.span,
                    "expected history expression",
                ));
            }
        };
        if self.eat("*") {
            self.depth(depth + 1)?;
            let span = Span {
                end: self.tokens[self.at - 1].span.end,
                ..self.nodes[child].span
            };
            self.node(Expr::Unary(Op::Star, child), span)
        } else {
            Ok(child)
        }
    }
    fn predicate(&mut self, level: usize, depth: usize) -> Result<usize, Diagnostic> {
        if level < 2 {
            let child = self.predicate(level + 1, depth)?;
            let (word, op) = [("or", Op::Or), ("and", Op::And)][level];
            if self.peek().text != word {
                return Ok(child);
            }
            let start = self.nodes[child].span;
            let mut children = Vec::new();
            push(&mut children, child, start)?;
            while self.eat(word) {
                let next = self.predicate(level + 1, depth)?;
                push(&mut children, next, self.nodes[next].span)?;
            }
            let end = self.nodes[*children.last().expect("nonempty")].span.end;
            return self.node(Expr::List(op, children), Span { end, ..start });
        }
        self.depth(depth)?;
        let t = self.peek();
        if self.eat("(") {
            let child = self.predicate(0, depth + 1)?;
            self.expect(")")?;
            return Ok(child);
        }
        if self.eat("true") {
            return self.node(Expr::True, t.span);
        }
        if self.eat("false") {
            return self.node(Expr::False, t.span);
        }
        if t.text == "not" {
            return Err(Diagnostic::new(
                Code::Unsupported,
                t.span,
                "use != or whole-history ! outside event",
            ));
        }
        let coordinate = self.name()?;
        let equal = if self.eat("==") {
            true
        } else {
            self.expect("!=")?;
            false
        };
        let value = self.value(true, true)?;
        let end = value.span().end;
        self.node(Expr::Atom(coordinate, equal, value), Span { end, ..t.span })
    }
}

fn duplicate<'a>(names: impl Iterator<Item = Name<'a>>, name: Name<'a>) -> Result<(), Diagnostic> {
    if let Some(previous) = names.into_iter().find(|n| n.text == name.text) {
        let mut error = Diagnostic::new(Code::DuplicateName, name.span, "duplicate name");
        error.related = Some(previous.span);
        Err(error)
    } else {
        Ok(())
    }
}
