use crate::{
    Diagnostic, Document, Error, ErrorKind, Kind, Limits, Literal, NamedRule, Span, Vocabulary,
};
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use history_syntax::{
    Arity, AtomPattern, Comparison, Component, ComponentPattern, Event, Head, RegexExpr, Rule,
    RuleMode, TestExpr,
};

const RESERVED: &[&str] = &[
    "schema",
    "let",
    "rule",
    "Candidate",
    "Event",
    "History",
    "bind",
    "where",
    "exists",
    "active",
    "reset",
    "any",
    "empty",
    "never",
    "also",
    "either",
    "complement",
    "require",
    "forbid",
    "diagnostic",
    "deny",
    "fix",
    "and",
    "or",
    "not",
    "true",
    "false",
    "algebra",
    "single",
    "concat",
    "choice",
    "intersection",
    "star",
    "negate",
    "any_of",
    "all_of",
];
const UNSUPPORTED: &[&str] = &[
    "summarize",
    "join",
    "scan",
    "project",
    "extend",
    "take",
    "count",
    "window",
    "ago",
    "datetime",
    "timespan",
    "sort",
    "order",
    "union",
    "invoke",
    "evaluate",
];

fn error(kind: ErrorKind, span: Span, message: impl Into<String>) -> Error {
    Error {
        kind,
        span,
        message: message.into(),
    }
}

#[derive(Clone, Copy)]
struct Token<'a> {
    text: &'a str,
    span: Span,
}

fn lex(source: &str, limits: Limits) -> Result<Vec<Token<'_>>, Error> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if source[i..].starts_with("//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let start = i;
        if tokens.len() == limits.tokens {
            return Err(error(
                ErrorKind::Limit,
                Span { start, end: start },
                "token budget exceeded",
            ));
        }
        match bytes[i] {
            b'"' => {
                i += 1;
                let mut closed = false;
                while i < bytes.len() {
                    if i - start > limits.literal_bytes + 1 {
                        return Err(error(
                            ErrorKind::Limit,
                            Span { start, end: i },
                            "literal budget exceeded",
                        ));
                    }
                    match bytes[i] {
                        b'"' => {
                            i += 1;
                            closed = true;
                            break;
                        }
                        b'\\' => {
                            i += 1;
                            if i == bytes.len() || !b"\"\\nrt".contains(&bytes[i]) {
                                return Err(error(
                                    ErrorKind::Literal,
                                    Span { start, end: i },
                                    "unsupported string escape",
                                ));
                            }
                            i += 1;
                        }
                        b'\n' | b'\r' | 0..=31 => {
                            return Err(error(
                                ErrorKind::Literal,
                                Span { start, end: i + 1 },
                                "unescaped control character",
                            ));
                        }
                        _ => i += 1,
                    }
                }
                if !closed {
                    return Err(error(
                        ErrorKind::Syntax,
                        Span { start, end: i },
                        "unterminated string",
                    ));
                }
                if i - start - 2 > limits.literal_bytes {
                    return Err(error(
                        ErrorKind::Limit,
                        Span { start, end: i },
                        "literal budget exceeded",
                    ));
                }
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                i += 1;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                if i - start > limits.literal_bytes {
                    return Err(error(
                        ErrorKind::Limit,
                        Span { start, end: i },
                        "identifier budget exceeded",
                    ));
                }
            }
            b'0'..=b'9' => {
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i - start > limits.literal_bytes {
                    return Err(error(
                        ErrorKind::Limit,
                        Span { start, end: i },
                        "integer budget exceeded",
                    ));
                }
            }
            b'=' | b'!' if i + 1 < bytes.len() && bytes[i + 1] == b'=' => i += 2,
            b'(' | b')' | b'{' | b'}' | b',' | b':' | b';' | b'|' | b'=' => i += 1,
            _ => {
                return Err(error(
                    ErrorKind::Unsupported,
                    Span {
                        start,
                        end: start + 1,
                    },
                    "unsupported character or operator",
                ));
            }
        }
        tokens.push(Token {
            text: &source[start..i],
            span: Span { start, end: i },
        });
    }
    Ok(tokens)
}

#[derive(Clone)]
struct Binding {
    name: String,
    coordinate: usize,
    pattern: String,
}

#[derive(Clone)]
enum Expr<E: Event> {
    Selector(Head<E>, Vec<Binding>),
    Predicate(TestExpr<E>),
    Language(RegexExpr<E>),
}

impl<E: Event> Expr<E> {
    fn kind(&self) -> Kind {
        match self {
            Self::Selector(..) => Kind::Selector,
            Self::Predicate(_) => Kind::Predicate,
            Self::Language(_) => Kind::Language,
        }
    }
}

struct Definition<E: Event> {
    name: String,
    parameters: Vec<Binding>,
    expression: Expr<E>,
    nodes: usize,
    depth: usize,
}

struct Tree<E: Event> {
    expression: Expr<E>,
    nodes: usize,
    depth: usize,
}

impl<E: Event> Tree<E> {
    fn dispose(self) {
        if let Expr::Language(tail) = self.expression {
            Rule::new(RuleMode::Require, Head::new([]), tail).dispose();
        }
    }
}

struct Parser<'a, E: Event, V: Vocabulary<E>> {
    tokens: Vec<Token<'a>>,
    at: usize,
    end: usize,
    vocabulary: &'a V,
    limits: Limits,
    spent: usize,
    recursion: usize,
    definitions: Vec<Definition<E>>,
    names: Vec<String>,
    environment: Vec<Binding>,
    rules: Vec<NamedRule<E>>,
    in_rule: bool,
}

pub(super) fn parse<E: Event, V: Vocabulary<E>>(
    source: &str,
    vocabulary: &V,
    limits: Limits,
) -> Result<Document<E>, Error> {
    let origin = Span {
        start: 0,
        end: source.len(),
    };
    if limits.source_bytes > 262_144
        || limits.tokens > 32_768
        || limits.literal_bytes > 4_096
        || limits.nesting > 64
        || limits.nodes > 65_536
        || limits.rules > 512
    {
        return Err(error(
            ErrorKind::Limit,
            origin,
            "configured limit exceeds hard cap",
        ));
    }
    if source.len() > limits.source_bytes {
        return Err(error(
            ErrorKind::Limit,
            origin,
            "source byte budget exceeded",
        ));
    }
    let fields = vocabulary.fields();
    if fields.len() != E::Arity::value()
        || fields.iter().enumerate().any(|(i, field)| {
            !identifier(field)
                || RESERVED.contains(field)
                || UNSUPPORTED.contains(field)
                || fields[..i].contains(field)
        })
    {
        return Err(error(
            ErrorKind::Schema,
            origin,
            "invalid host field layout",
        ));
    }
    let mut parser = Parser {
        tokens: lex(source, limits)?,
        at: 0,
        end: source.len(),
        vocabulary,
        limits,
        spent: 0,
        recursion: 0,
        definitions: Vec::new(),
        names: Vec::new(),
        environment: Vec::new(),
        rules: Vec::new(),
        in_rule: false,
    };
    parser.file()?;
    Ok(Document {
        rules: core::mem::take(&mut parser.rules),
    })
}

impl<E: Event, V: Vocabulary<E>> Drop for Parser<'_, E, V> {
    fn drop(&mut self) {
        for item in self.rules.drain(..) {
            item.rule.dispose();
        }
    }
}

fn identifier(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

impl<'a, E: Event, V: Vocabulary<E>> Parser<'a, E, V> {
    fn token(&self) -> Token<'a> {
        self.tokens.get(self.at).copied().unwrap_or(Token {
            text: "",
            span: Span {
                start: self.end,
                end: self.end,
            },
        })
    }
    fn fail(&self, kind: ErrorKind, message: impl Into<String>) -> Error {
        error(kind, self.token().span, message)
    }
    fn eat(&mut self, text: &str) -> bool {
        if self.token().text == text && !text.is_empty() {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn expect(&mut self, text: &str) -> Result<(), Error> {
        if self.eat(text) {
            Ok(())
        } else {
            Err(self.fail(
                if UNSUPPORTED.contains(&self.token().text) {
                    ErrorKind::Unsupported
                } else {
                    ErrorKind::Syntax
                },
                format!("expected {text}"),
            ))
        }
    }
    fn ident(&mut self) -> Result<String, Error> {
        let token = self.token();
        if !identifier(token.text) || RESERVED.contains(&token.text) {
            return Err(self.fail(ErrorKind::Syntax, "expected identifier"));
        }
        if UNSUPPORTED.contains(&token.text) {
            return Err(self.fail(ErrorKind::Unsupported, "unsupported query feature"));
        }
        self.at += 1;
        Ok(token.text.to_string())
    }
    fn local_name(&mut self) -> Result<String, Error> {
        let name = self.ident()?;
        if self.vocabulary.fields().contains(&name.as_str()) {
            return Err(error(
                ErrorKind::Duplicate,
                self.tokens[self.at - 1].span,
                "field name cannot be reused",
            ));
        }
        Ok(name)
    }
    fn field(&mut self) -> Result<usize, Error> {
        let token = self.token();
        let coordinate = self
            .vocabulary
            .fields()
            .iter()
            .position(|f| *f == token.text)
            .ok_or_else(|| self.fail(ErrorKind::UnknownName, "unknown coordinate"))?;
        self.at += 1;
        Ok(coordinate)
    }
    fn charge(&mut self, nodes: usize) -> Result<(), Error> {
        if nodes > self.limits.nodes.saturating_sub(self.spent) {
            return Err(self.fail(ErrorKind::Limit, "node/static expansion budget exceeded"));
        }
        self.spent += nodes;
        Ok(())
    }
    fn depth(&self, depth: usize) -> Result<(), Error> {
        if depth > self.limits.nesting {
            Err(self.fail(ErrorKind::Limit, "generated tree nesting exceeded"))
        } else {
            Ok(())
        }
    }
    fn nested<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, Error>) -> Result<T, Error> {
        if self.recursion >= self.limits.nesting {
            return Err(self.fail(ErrorKind::Limit, "parser nesting exceeded"));
        }
        self.recursion += 1;
        let result = f(self);
        self.recursion -= 1;
        result
    }
    fn leaf(&mut self, expression: Expr<E>) -> Result<Tree<E>, Error> {
        self.charge(1)?;
        self.depth(1)?;
        Ok(Tree {
            expression,
            nodes: 1,
            depth: 1,
        })
    }
    fn file(&mut self) -> Result<(), Error> {
        self.expect("schema")?;
        let name = self.ident()?;
        if name != self.vocabulary.schema() {
            return Err(error(
                ErrorKind::Schema,
                self.tokens[self.at - 1].span,
                "schema identity mismatch",
            ));
        }
        self.expect("(")?;
        for i in 0..self.vocabulary.fields().len() {
            if i != 0 {
                self.expect(",")?;
            }
            let token = self.token();
            if token.text != self.vocabulary.fields()[i] {
                return Err(self.fail(ErrorKind::Schema, "schema coordinate order mismatch"));
            }
            self.at += 1;
        }
        self.expect(")")?;
        self.expect(";")?;
        while !self.token().text.is_empty() {
            let span = self.token().span;
            let is_rule = if self.eat("let") {
                false
            } else if self.eat("rule") {
                true
            } else {
                return Err(self.fail(ErrorKind::Unsupported, "expected let or rule declaration"));
            };
            let name = self.local_name()?;
            if self.names.contains(&name) {
                return Err(error(
                    ErrorKind::Duplicate,
                    self.tokens[self.at - 1].span,
                    "duplicate declaration",
                ));
            }
            self.expect("=")?;
            if is_rule {
                self.rule(name.clone(), span)?;
            } else {
                self.definition(name.clone())?;
            }
            self.names.push(name);
        }
        Ok(())
    }
    fn definition(&mut self, name: String) -> Result<(), Error> {
        let function = self.eat("(");
        if function {
            if !self.eat(")") {
                loop {
                    let parameter = self.local_name()?;
                    if self.environment.iter().any(|b| b.name == parameter) {
                        return Err(self.fail(ErrorKind::Duplicate, "duplicate parameter"));
                    }
                    self.expect(":")?;
                    let coordinate = self.field()?;
                    self.charge(1)?;
                    self.environment.push(Binding {
                        name: parameter,
                        coordinate,
                        pattern: format!("@parameter{}", self.environment.len()),
                    });
                    if self.eat(")") {
                        break;
                    }
                    self.expect(",")?;
                }
            }
            self.expect("{")?;
        }
        let tree = self.expression()?;
        if function {
            if tree.expression.kind() == Kind::Selector {
                return Err(self.fail(ErrorKind::Kind, "parameterized selectors are unsupported"));
            }
            self.expect("}")?;
        }
        self.expect(";")?;
        self.definitions.push(Definition {
            name,
            parameters: core::mem::take(&mut self.environment),
            expression: tree.expression,
            nodes: tree.nodes,
            depth: tree.depth,
        });
        Ok(())
    }
    fn rule(&mut self, name: String, start: Span) -> Result<(), Error> {
        if self.rules.len() >= self.limits.rules {
            return Err(self.fail(ErrorKind::Limit, "rule budget exceeded"));
        }
        let selector = if self.token().text == "Candidate" {
            self.selector()?
        } else {
            self.reference()?
        };
        let Expr::Selector(head, bindings) = selector.expression else {
            return Err(self.fail(ErrorKind::Kind, "rule requires a candidate selector"));
        };
        self.environment = bindings;
        self.in_rule = true;
        self.expect("|")?;
        let mode = if self.eat("require") {
            RuleMode::Require
        } else if self.eat("forbid") {
            RuleMode::Forbid
        } else {
            return Err(self.fail(ErrorKind::Syntax, "expected require or forbid"));
        };
        let tree = self.history()?;
        let Expr::Language(tail) = tree.expression else {
            return Err(self.fail(ErrorKind::Kind, "rule tail must be a history language"));
        };
        let mut pending = PendingRule(Some(Rule::new(mode, head, tail)));
        self.expect("|")?;
        let diagnostic = if self.eat("deny") {
            let message = self.string()?;
            let mut fixes = Vec::new();
            if self.eat("fix") {
                loop {
                    self.charge(1)?;
                    fixes.push(self.string()?);
                    if !self.eat(",") {
                        break;
                    }
                }
            }
            Diagnostic { message, fixes }
        } else if self.eat("diagnostic") {
            let token = self.token();
            let id = self.ident()?;
            let diagnostic = self.vocabulary.diagnostic(&id).ok_or_else(|| {
                error(
                    ErrorKind::UnknownName,
                    token.span,
                    "unknown diagnostic registration",
                )
            })?;
            if diagnostic.message.len() > self.limits.literal_bytes
                || diagnostic.fixes.len() > self.limits.tokens
                || diagnostic
                    .fixes
                    .iter()
                    .any(|f| f.len() > self.limits.literal_bytes)
            {
                return Err(error(
                    ErrorKind::Limit,
                    token.span,
                    "host diagnostic exceeds limits",
                ));
            }
            self.charge(diagnostic.fixes.len() + 1)?;
            diagnostic
        } else {
            return Err(self.fail(ErrorKind::Syntax, "expected deny or diagnostic"));
        };
        let end = self.token().span.end;
        self.expect(";")?;
        self.charge(1)?;
        self.rules.push(NamedRule {
            name,
            span: Span {
                start: start.start,
                end,
            },
            rule: pending.0.take().expect("pending typed rule"),
            diagnostic,
        });
        self.environment.clear();
        self.in_rule = false;
        Ok(())
    }
    fn expression(&mut self) -> Result<Tree<E>, Error> {
        match self.token().text {
            "Candidate" => self.selector(),
            "Event" => self.event(),
            "History" => self.history(),
            _ => {
                let tree = self.reference()?;
                if tree.expression.kind() == Kind::Language {
                    self.history_stages(tree)
                } else {
                    Ok(tree)
                }
            }
        }
    }
    fn selector(&mut self) -> Result<Tree<E>, Error> {
        self.expect("Candidate")?;
        let arity = E::Arity::value();
        self.charge(arity + 1)?;
        self.depth(1)?;
        let mut slots = (0..arity)
            .map(|i| ComponentPattern::Variable(format!("@wildcard{i}")))
            .collect::<Vec<_>>();
        let mut assigned = vec![false; arity];
        let mut bindings: Vec<Binding> = Vec::new();
        let mut bound = false;
        while self.token().text == "|" {
            let next = self.tokens.get(self.at + 1).map(|t| t.text);
            if next != Some("bind") && next != Some("where") {
                break;
            }
            self.at += 1;
            if self.eat("bind") {
                if bound {
                    return Err(self.fail(ErrorKind::Head, "only one bind stage is allowed"));
                }
                bound = true;
                loop {
                    let coordinate = self.field()?;
                    self.expect("=")?;
                    let name = self.local_name()?;
                    if assigned[coordinate] || bindings.iter().any(|b| b.name == name) {
                        return Err(self.fail(ErrorKind::Head, "repeated coordinate or binding"));
                    }
                    assigned[coordinate] = true;
                    slots[coordinate] = ComponentPattern::Variable(name.clone());
                    bindings.push(Binding {
                        pattern: name.clone(),
                        name,
                        coordinate,
                    });
                    if !self.eat(",") {
                        break;
                    }
                }
            } else {
                self.expect("where")?;
                loop {
                    let coordinate = self.field()?;
                    self.expect("==")?;
                    let pattern = self.value(coordinate, false)?;
                    if assigned[coordinate] {
                        return Err(self.fail(
                            ErrorKind::Head,
                            "coordinate cannot be restricted twice or bound and restricted",
                        ));
                    }
                    assigned[coordinate] = true;
                    slots[coordinate] = pattern;
                    if !self.eat("and") {
                        break;
                    }
                }
            }
        }
        Ok(Tree {
            expression: Expr::Selector(Head::new(slots), bindings),
            nodes: arity + 1,
            depth: 1,
        })
    }
    fn string(&mut self) -> Result<String, Error> {
        let token = self.token();
        if !token.text.starts_with('"') {
            return Err(self.fail(ErrorKind::Literal, "expected string literal"));
        }
        self.at += 1;
        let mut result = String::new();
        let mut chars = token.text[1..token.text.len() - 1].chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                result.push(match chars.next() {
                    Some('"') => '"',
                    Some('\\') => '\\',
                    Some('n') => '\n',
                    Some('r') => '\r',
                    Some('t') => '\t',
                    _ => return Err(error(ErrorKind::Literal, token.span, "invalid escape")),
                });
            } else {
                result.push(c);
            }
        }
        Ok(result)
    }
    fn value(
        &mut self,
        coordinate: usize,
        variables: bool,
    ) -> Result<ComponentPattern<E::Component>, Error> {
        let token = self.token();
        let literal = if token.text.starts_with('"') {
            Literal::String(self.string()?)
        } else if token
            .text
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_digit)
        {
            self.at += 1;
            Literal::Integer(
                token
                    .text
                    .parse()
                    .map_err(|_| error(ErrorKind::Literal, token.span, "integer exceeds u64"))?,
            )
        } else if variables {
            let name = self.ident()?;
            let binding = self
                .environment
                .iter()
                .find(|b| b.name == name)
                .ok_or_else(|| error(ErrorKind::Variable, token.span, "unbound variable"))?;
            if binding.coordinate != coordinate {
                return Err(error(
                    ErrorKind::Variable,
                    token.span,
                    "variable belongs to a different coordinate",
                ));
            }
            return Ok(ComponentPattern::Variable(binding.pattern.clone()));
        } else {
            return Err(self.fail(ErrorKind::Head, "candidate restrictions require literals"));
        };
        let constant = self
            .vocabulary
            .constant(Component::new(coordinate), &literal)
            .ok_or_else(|| {
                error(
                    ErrorKind::Literal,
                    token.span,
                    "unknown or invalid constant",
                )
            })?;
        if E::coordinate(constant) != coordinate {
            return Err(error(
                ErrorKind::Schema,
                token.span,
                "host returned a wrong-coordinate constant",
            ));
        }
        Ok(ComponentPattern::Constant(constant))
    }
    fn reference(&mut self) -> Result<Tree<E>, Error> {
        let token = self.token();
        let name = self.ident()?;
        let index = self
            .definitions
            .iter()
            .position(|d| d.name == name)
            .ok_or_else(|| {
                error(
                    if self.names.contains(&name) {
                        ErrorKind::Kind
                    } else {
                        ErrorKind::UnknownName
                    },
                    token.span,
                    "expected an earlier let definition (not a rule)",
                )
            })?;
        let count = self.definitions[index].parameters.len();
        let mut arguments = Vec::new();
        if self.eat("(") {
            for i in 0..count {
                if i != 0 {
                    self.expect(",")?;
                }
                let coordinate = self.definitions[index].parameters[i].coordinate;
                self.charge(1)?;
                arguments.push(self.value(coordinate, true)?);
            }
            self.expect(")")?;
        } else if count != 0 {
            return Err(error(
                ErrorKind::Kind,
                token.span,
                "missing typed arguments",
            ));
        }
        let nodes = self.definitions[index].nodes;
        let depth = self.definitions[index].depth;
        self.charge(nodes)?;
        self.depth(depth)?;
        let definition = &self.definitions[index];
        let mut expression = definition.expression.clone();
        // Substitution visits each original pattern once: inserted argument names
        // cannot be captured or substituted again by a same-spelled local parameter.
        match &mut expression {
            Expr::Predicate(test) => substitute_test(test, &definition.parameters, &arguments),
            Expr::Language(regex) => substitute_regex(regex, &definition.parameters, &arguments),
            Expr::Selector(..) => {}
        }
        Ok(Tree {
            expression,
            nodes,
            depth,
        })
    }
    fn event(&mut self) -> Result<Tree<E>, Error> {
        self.expect("Event")?;
        let mut tree = None;
        while self.token().text == "|"
            && self
                .tokens
                .get(self.at + 1)
                .is_some_and(|t| t.text == "where")
        {
            self.at += 2;
            let next = self.predicate()?;
            tree = Some(match tree {
                Some(previous) => self.boolean(previous, next, true)?,
                None => next,
            });
        }
        match tree {
            Some(tree) => Ok(tree),
            None => self.leaf(Expr::Predicate(TestExpr::True)),
        }
    }
    fn predicate(&mut self) -> Result<Tree<E>, Error> {
        self.nested(|p| {
            let mut left = p.conjunction()?;
            while p.eat("or") {
                let right = p.conjunction()?;
                left = p.boolean(left, right, false)?;
            }
            Ok(left)
        })
    }
    fn conjunction(&mut self) -> Result<Tree<E>, Error> {
        let mut left = self.unary()?;
        while self.eat("and") {
            let right = self.unary()?;
            left = self.boolean(left, right, true)?;
        }
        Ok(left)
    }
    fn unary(&mut self) -> Result<Tree<E>, Error> {
        if ["any_of", "all_of"].contains(&self.token().text) {
            let and = self.eat("all_of");
            if !and {
                self.expect("any_of")?;
            }
            self.expect("(")?;
            self.charge(1)?;
            let mut children = Vec::new();
            let mut nodes = 1;
            let mut depth = 1;
            if !self.eat(")") {
                loop {
                    let child = self.predicate()?;
                    nodes += child.nodes;
                    depth = depth.max(child.depth + 1);
                    self.depth(depth)?;
                    let Expr::Predicate(test) = child.expression else {
                        return Err(self.fail(ErrorKind::Kind, "expected predicate"));
                    };
                    children.push(test);
                    if self.eat(")") {
                        break;
                    }
                    self.expect(",")?;
                }
            }
            return Ok(Tree {
                expression: Expr::Predicate(if and {
                    TestExpr::And(children)
                } else {
                    TestExpr::Or(children)
                }),
                nodes,
                depth,
            });
        }
        if self.eat("not") {
            self.expect("(")?;
            let mut tree = self.predicate()?;
            self.expect(")")?;
            if let Expr::Predicate(test) = &mut tree.expression {
                negate(test);
            }
            return Ok(tree);
        }
        if self.eat("(") {
            let tree = self.predicate()?;
            self.expect(")")?;
            return Ok(tree);
        }
        if self.eat("true") {
            return self.leaf(Expr::Predicate(TestExpr::True));
        }
        if self.eat("false") {
            return self.leaf(Expr::Predicate(TestExpr::False));
        }
        if self.vocabulary.fields().contains(&self.token().text) {
            let coordinate = self.field()?;
            let comparison = if self.eat("==") {
                Comparison::Eq
            } else if self.eat("!=") {
                Comparison::Neq
            } else {
                return Err(self.fail(ErrorKind::Syntax, "expected == or !="));
            };
            let pattern = self.value(coordinate, true)?;
            return self.leaf(Expr::Predicate(TestExpr::atom(
                comparison,
                AtomPattern::new(Component::new(coordinate), pattern),
            )));
        }
        let tree = self.reference()?;
        if tree.expression.kind() != Kind::Predicate {
            return Err(self.fail(ErrorKind::Kind, "expected event predicate"));
        }
        Ok(tree)
    }
    fn boolean(&mut self, left: Tree<E>, right: Tree<E>, and: bool) -> Result<Tree<E>, Error> {
        self.charge(1)?;
        let depth = left.depth.max(right.depth) + 1;
        self.depth(depth)?;
        let (Expr::Predicate(l), Expr::Predicate(r)) = (left.expression, right.expression) else {
            return Err(self.fail(ErrorKind::Kind, "Boolean operators require predicates"));
        };
        Ok(Tree {
            expression: Expr::Predicate(if and {
                TestExpr::and([l, r])
            } else {
                TestExpr::or([l, r])
            }),
            nodes: left.nodes + right.nodes + 1,
            depth,
        })
    }
    fn predicate_arg(&mut self) -> Result<Tree<E>, Error> {
        let tree = if self.eat("(") {
            let tree = self.event()?;
            self.expect(")")?;
            tree
        } else {
            self.reference()?
        };
        if tree.expression.kind() != Kind::Predicate {
            return Err(self.fail(
                ErrorKind::Kind,
                "history constructor requires event predicate",
            ));
        }
        Ok(tree)
    }
    fn history(&mut self) -> Result<Tree<E>, Error> {
        self.nested(|p| {
            let tree = if p.eat("History") {
                p.expect("|")?;
                if p.eat("algebra") {
                    p.algebra()?
                } else if p.eat("any") {
                    p.leaf(Expr::Language(RegexExpr::All))?
                } else if p.eat("empty") {
                    p.leaf(Expr::Language(RegexExpr::Epsilon))?
                } else if p.eat("never") {
                    p.leaf(Expr::Language(RegexExpr::Empty))?
                } else {
                    let active = if p.eat("exists") {
                        false
                    } else if p.eat("active") {
                        true
                    } else {
                        return Err(p.fail(
                            ErrorKind::Unsupported,
                            "unsupported History constructor; History cannot be filtered",
                        ));
                    };
                    p.expect("(")?;
                    let trigger = p.predicate_arg()?;
                    let stable = if active {
                        p.expect(",")?;
                        p.expect("reset")?;
                        p.expect("=")?;
                        Some(p.predicate_arg()?)
                    } else {
                        None
                    };
                    p.expect(")")?;
                    let depth = if let Some(ref stable) = stable {
                        (stable.depth + 3).max(trigger.depth + 2)
                    } else {
                        trigger.depth + 2
                    };
                    p.depth(depth)?;
                    p.charge(if active { 5 } else { 4 })?;
                    let Expr::Predicate(trigger_test) = trigger.expression else {
                        return Err(p.fail(ErrorKind::Kind, "expected trigger predicate"));
                    };
                    let (suffix, nodes) = if let Some(stable) = stable {
                        let Expr::Predicate(mut reset) = stable.expression else {
                            return Err(p.fail(ErrorKind::Kind, "expected reset predicate"));
                        };
                        negate(&mut reset);
                        (
                            RegexExpr::star(RegexExpr::test(reset)),
                            trigger.nodes + stable.nodes + 5,
                        )
                    } else {
                        (RegexExpr::All, trigger.nodes + 4)
                    };
                    Tree {
                        expression: Expr::Language(RegexExpr::concat([
                            RegexExpr::All,
                            RegexExpr::test(trigger_test),
                            suffix,
                        ])),
                        nodes,
                        depth,
                    }
                }
            } else if p.eat("(") {
                let tree = p.history()?;
                if let Err(error) = p.expect(")") {
                    tree.dispose();
                    return Err(error);
                }
                tree
            } else {
                let tree = p.reference()?;
                if tree.expression.kind() != Kind::Language {
                    return Err(p.fail(ErrorKind::Kind, "expected history language"));
                }
                tree
            };
            p.history_stages(tree)
        })
    }
    fn history_stages(&mut self, mut left: Tree<E>) -> Result<Tree<E>, Error> {
        loop {
            if self.token().text != "|" {
                break;
            }
            let stage = self.tokens.get(self.at + 1).map(|t| t.text).unwrap_or("");
            if !["also", "either", "complement"].contains(&stage) {
                break;
            }
            if left.depth > self.limits.nesting {
                left.dispose();
                return Err(self.fail(
                    ErrorKind::Limit,
                    "combine deep generated languages inside algebra",
                ));
            }
            self.at += 2;
            self.charge(1)?;
            if stage == "complement" {
                self.depth(left.depth + 1)?;
                let Expr::Language(language) = left.expression else {
                    return Err(self.fail(ErrorKind::Kind, "complement requires language"));
                };
                left = Tree {
                    expression: Expr::Language(RegexExpr::complement(language)),
                    nodes: left.nodes + 1,
                    depth: left.depth + 1,
                };
            } else {
                // A stage takes one primary; parentheses admit an entire pipeline.
                let right = if self.eat("(") {
                    let right = self.history()?;
                    if let Err(error) = self.expect(")") {
                        left.dispose();
                        right.dispose();
                        return Err(error);
                    }
                    right
                } else {
                    self.reference()?
                };
                let depth = left.depth.max(right.depth) + 1;
                if let Err(error) = self.depth(depth) {
                    left.dispose();
                    right.dispose();
                    return Err(error);
                }
                let (Expr::Language(l), Expr::Language(r)) = (left.expression, right.expression)
                else {
                    return Err(self.fail(ErrorKind::Kind, "also/either require history languages"));
                };
                left = Tree {
                    expression: Expr::Language(if stage == "also" {
                        RegexExpr::intersect([l, r])
                    } else {
                        RegexExpr::union([l, r])
                    }),
                    nodes: left.nodes + right.nodes + 1,
                    depth,
                };
            }
        }
        Ok(left)
    }

    fn algebra(&mut self) -> Result<Tree<E>, Error> {
        if !self.in_rule {
            return Err(self.fail(
                ErrorKind::Kind,
                "algebra is an inline rule language; use ordinary named pipelines for helpers",
            ));
        }
        self.expect("{")?;
        let mut stack = AlgebraStack::<E>(Vec::new());
        while !self.eat("}") {
            let instruction = self.token();
            if self.eat("single") {
                let tree = self.predicate_arg()?;
                self.charge(1)?;
                let Expr::Predicate(test) = tree.expression else {
                    return Err(self.fail(ErrorKind::Kind, "single requires predicate"));
                };
                stack
                    .0
                    .push((RegexExpr::Test(test), tree.nodes + 1, tree.depth + 1));
            } else if self.eat("any") {
                self.charge(1)?;
                stack.0.push((RegexExpr::All, 1, 1));
            } else if self.eat("empty") {
                self.charge(1)?;
                stack.0.push((RegexExpr::Epsilon, 1, 1));
            } else if self.eat("never") {
                self.charge(1)?;
                stack.0.push((RegexExpr::Empty, 1, 1));
            } else if self.eat("star") || self.eat("negate") {
                self.charge(1)?;
                let (_, _, depth) = stack
                    .0
                    .last()
                    .ok_or_else(|| self.fail(ErrorKind::Syntax, "algebra stack underflow"))?;
                if *depth >= 512 {
                    return Err(self.fail(ErrorKind::Limit, "algebra tree depth exceeds 512"));
                }
                let (child, nodes, depth) = stack.0.pop().expect("checked stack");
                let regex = if instruction.text == "star" {
                    RegexExpr::star(child)
                } else {
                    RegexExpr::complement(child)
                };
                stack.0.push((regex, nodes + 1, depth + 1));
            } else if ["concat", "choice", "intersection"].contains(&instruction.text) {
                self.at += 1;
                let count_token = self.token();
                if !count_token.text.bytes().all(|b| b.is_ascii_digit())
                    || count_token.text.is_empty()
                {
                    return Err(self.fail(ErrorKind::Syntax, "expected algebra operand count"));
                }
                let count: usize = count_token
                    .text
                    .parse()
                    .map_err(|_| self.fail(ErrorKind::Limit, "operand count overflow"))?;
                self.at += 1;
                if count > stack.0.len() {
                    return Err(self.fail(ErrorKind::Syntax, "algebra stack underflow"));
                }
                self.charge(1)?;
                let offset = stack.0.len() - count;
                let depth = stack.0[offset..]
                    .iter()
                    .map(|(_, _, d)| *d + 1)
                    .max()
                    .unwrap_or(1);
                if depth > 512 {
                    return Err(self.fail(ErrorKind::Limit, "algebra tree depth exceeds 512"));
                }
                let mut nodes = 1;
                let children = stack
                    .0
                    .drain(offset..)
                    .map(|(r, n, _)| {
                        nodes += n;
                        r
                    })
                    .collect();
                let regex = match instruction.text {
                    "concat" => RegexExpr::Concat(children),
                    "choice" => RegexExpr::Union(children),
                    _ => RegexExpr::Intersect(children),
                };
                stack.0.push((regex, nodes, depth));
            } else {
                return Err(self.fail(ErrorKind::Unsupported, "unknown algebra instruction"));
            }
            self.expect(";")?;
        }
        if stack.0.len() != 1 {
            return Err(self.fail(ErrorKind::Syntax, "algebra must leave exactly one language"));
        }
        let (regex, nodes, depth) = stack.0.pop().expect("checked stack");
        Ok(Tree {
            expression: Expr::Language(regex),
            nodes,
            depth,
        })
    }
}

struct AlgebraStack<E: Event>(Vec<(RegexExpr<E>, usize, usize)>);

struct PendingRule<E: Event>(Option<Rule<E>>);
impl<E: Event> Drop for PendingRule<E> {
    fn drop(&mut self) {
        if let Some(rule) = self.0.take() {
            rule.dispose();
        }
    }
}

impl<E: Event> Drop for AlgebraStack<E> {
    fn drop(&mut self) {
        for (tail, _, _) in self.0.drain(..) {
            Rule::new(RuleMode::Require, Head::new([]), tail).dispose();
        }
    }
}

fn substitute_pattern<E: Event>(
    pattern: &mut ComponentPattern<E::Component>,
    parameters: &[Binding],
    arguments: &[ComponentPattern<E::Component>],
) {
    if let ComponentPattern::Variable(name) = pattern
        && let Some(index) = parameters.iter().position(|p| p.pattern == *name)
    {
        *pattern = arguments[index].clone();
    }
}

fn substitute_test<E: Event>(
    test: &mut TestExpr<E>,
    parameters: &[Binding],
    arguments: &[ComponentPattern<E::Component>],
) {
    match test {
        TestExpr::Atom { pattern, .. } => {
            substitute_pattern::<E>(&mut pattern.pattern, parameters, arguments)
        }
        TestExpr::And(children) | TestExpr::Or(children) => {
            for child in children {
                substitute_test(child, parameters, arguments);
            }
        }
        TestExpr::True | TestExpr::False => {}
    }
}

fn substitute_regex<E: Event>(
    regex: &mut RegexExpr<E>,
    parameters: &[Binding],
    arguments: &[ComponentPattern<E::Component>],
) {
    match regex {
        RegexExpr::Test(test) => substitute_test(test, parameters, arguments),
        RegexExpr::Union(children)
        | RegexExpr::Concat(children)
        | RegexExpr::Intersect(children) => {
            for child in children {
                substitute_regex(child, parameters, arguments);
            }
        }
        RegexExpr::Star(child) | RegexExpr::Not(child) => {
            substitute_regex(child, parameters, arguments)
        }
        RegexExpr::Empty | RegexExpr::All | RegexExpr::Epsilon => {}
    }
}

fn negate<E: Event>(test: &mut TestExpr<E>) {
    match test {
        TestExpr::True => *test = TestExpr::False,
        TestExpr::False => *test = TestExpr::True,
        TestExpr::Atom { comparison, .. } => *comparison = !*comparison,
        TestExpr::And(children) | TestExpr::Or(children) => {
            for child in children.iter_mut() {
                negate(child);
            }
            let children = core::mem::take(children);
            *test = if matches!(test, TestExpr::And(_)) {
                TestExpr::Or(children)
            } else {
                TestExpr::And(children)
            };
        }
    }
}
