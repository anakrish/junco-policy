mod support;
use history_syntax::{Component, Component3, ComponentPattern, RegexExpr, TestExpr};
use history_text::{
    Code, Limits, Literal, LowerError, Resolver, Source, SourceId, Vocabulary, lower, parse,
    parse_bytes,
};
use support::*;

fn source(text: &str) -> Source<'_> {
    Source {
        id: SourceId(9),
        text,
    }
}
fn doc(body: &str) -> String {
    format!("junco 1; schema \"lock/1\"; policy checks {{ {body} }}")
}
fn rule(tail: &str) -> String {
    doc(&format!(
        "rule r {{ candidate {{ resource: $r, action: $a, principal: $p, }}; require {tail}; }}"
    ))
}
fn code(text: &str) -> Code {
    match parse(source(text), Limits::default()) {
        Err(e) => e.code,
        Ok(parsed) => match lower::<Lock, _>(&parsed, &LockVocabulary).unwrap_err() {
            LowerError::Frontend(e) => e.code,
            LowerError::Resolver { .. } => Code::InvalidLiteral,
        },
    }
}

#[test]
fn typed_resolution_shuffled_heads_aliases_and_provenance() {
    let text = doc("const release: action = action.release;
        rule r { candidate { resource: $r, action: release, principal: $p, };
        require event { action == release and principal == $p }; }");
    let parsed = parse(source(&text), Limits::default()).unwrap();
    let typed = lower::<Lock, _>(&parsed, &LockVocabulary).unwrap();
    let entry = &typed.entries()[0];
    assert_eq!(
        entry.rule.head.slots(),
        &[
            ComponentPattern::variable("p"),
            ComponentPattern::Constant(Component3::C1(RELEASE)),
            ComponentPattern::variable("r")
        ]
    );
    assert!(
        entry
            .info
            .origins
            .iter()
            .all(|span| span.location(source(&text)).is_some())
    );
    assert!(
        entry
            .info
            .origins
            .iter()
            .any(|span| &text[span.start..span.end] == "principal == $p")
    );
}

#[test]
fn precedence_and_grouping_preserve_constructor_shape() {
    let text = rule("empty | epsilon & all >> !event { true or false and true }*");
    let parsed = parse(source(&text), Limits::default()).unwrap();
    let typed = lower::<Lock, _>(&parsed, &LockVocabulary).unwrap();
    assert_eq!(
        typed.entries()[0].rule.tail,
        RegexExpr::Union(vec![
            RegexExpr::Empty,
            RegexExpr::Intersect(vec![
                RegexExpr::Epsilon,
                RegexExpr::Concat(vec![
                    RegexExpr::All,
                    RegexExpr::complement(RegexExpr::star(RegexExpr::Test(TestExpr::Or(vec![
                        TestExpr::True,
                        TestExpr::And(vec![TestExpr::False, TestExpr::True])
                    ]))))
                ])
            ])
        ])
    );
    let text = rule("(all | empty) >> (epsilon*)*");
    let parsed = parse(source(&text), Limits::default()).unwrap();
    let typed = lower::<Lock, _>(&parsed, &LockVocabulary).unwrap();
    assert_eq!(
        typed.entries()[0].rule.tail,
        RegexExpr::Concat(vec![
            RegexExpr::Union(vec![RegexExpr::All, RegexExpr::Empty]),
            RegexExpr::star(RegexExpr::star(RegexExpr::Epsilon))
        ])
    );
}

#[test]
fn lexical_json_comments_and_scalar_locations() {
    let text = "junco 1;\r\nschema \"f\\u006cow/1\"; // comment\r\npolicy p {
        const t: label = \"untrusted\"; const s: label = \"sink\";
        rule r { candidate { principal: $p, handle: $h, action: action.contact, label: s };
          forbid event { label == t }; } }";
    let parsed = parse(source(text), Limits::default()).unwrap();
    let typed = lower::<Flow, _>(&parsed, &FlowVocabulary).unwrap();
    let span = typed.entries()[0].info.span;
    assert_eq!(span.location(source(text)).unwrap().0, 5);

    let parsed = parse(
        source("junco 1; schema \"\\uD83D\\uDE00//\\\"\\\\\\/\\b\\f\\n\\r\\t\"; policy p {}"),
        Limits::default(),
    )
    .unwrap();
    assert!(
        matches!(lower::<Lock, _>(&parsed, &LockVocabulary), Err(LowerError::Frontend(e)) if e.code == Code::Schema)
    );
    for bad in [
        "\"\\uD800\"",
        "\"\\uDC00\"",
        "\"\\uD800\\u0041\"",
        "\"\\q\"",
        "\"\n\"",
        "\"unterminated",
    ] {
        let text = format!("junco 1; schema {bad}; policy p {{}}");
        assert_eq!(
            parse(source(&text), Limits::default()).unwrap_err().code,
            Code::InvalidString,
            "{bad}"
        );
    }
    assert_eq!(
        parse_bytes(SourceId(1), b"\xff", Limits::default())
            .unwrap_err()
            .code,
        Code::InvalidUtf8
    );
    assert_eq!(
        parse(source("\u{feff}junco 1;"), Limits::default())
            .unwrap_err()
            .code,
        Code::Unsupported
    );
    let unicode = source("// \u{1f600}\r\njunco 1; schema \"lock/1\"; policy p {}");
    let span = history_text::Span {
        source: unicode.id,
        start: 9,
        end: 9,
    };
    assert_eq!(span.location(unicode), Some((2, 1)));
}

#[test]
fn invalid_heads_names_bindings_constants_and_unsupported_features_fail() {
    for (body, expected) in [
        (
            "rule r { candidate { principal: $p, action: $a }; require all; }",
            Code::Head,
        ),
        (
            "rule r { candidate { principal: $p, action: $a, resource: $p }; require all; }",
            Code::WrongCoordinate,
        ),
        (
            "rule r { candidate { principal: $p, action: $a, resource: $r }; require event { resource == $p }; }",
            Code::WrongCoordinate,
        ),
        (
            "rule r { candidate { principal: $p, action: $a, resource: $r }; require event { resource == $other }; }",
            Code::UnboundVariable,
        ),
        (
            "rule r { candidate { principal: $p, action: $a, unknown: $r }; require all; }",
            Code::UnknownCoordinate,
        ),
        (
            "rule r { candidate { principal: $p, action: $a, principal: $r }; require all; }",
            Code::DuplicateName,
        ),
        (
            "const x: principal = 1; rule r { candidate { principal: $p, action: $a, resource: x }; require all; }",
            Code::WrongCoordinate,
        ),
        (
            "const x: principal = 1; const x: principal = 2;",
            Code::DuplicateName,
        ),
        (
            "rule r { candidate { principal: 1, action: action.read, resource: 1 }; require event { action == action.unknown }; }",
            Code::InvalidLiteral,
        ),
        (
            "rule r { candidate { principal: $p, action: $a, resource: missing }; require all; }",
            Code::UnknownAlias,
        ),
        (
            "rule r { candidate { principal: 4294967296, action: $a, resource: $r }; require all; }",
            Code::InvalidLiteral,
        ),
        (
            "rule r { candidate { principal: \"42\", action: $a, resource: $r }; require all; }",
            Code::InvalidLiteral,
        ),
        (
            "rule r { candidate { principal: $p, action: $a, resource: $r }; require event { principal == resource.x }; }",
            Code::WrongCoordinate,
        ),
    ] {
        assert_eq!(code(&doc(body)), expected, "{body}");
    }
    for tail in [
        "all**",
        "all all",
        "all?",
        "all+",
        "all{2}",
        "event { not true }",
        "event { principal == call(1) }",
        "all >>",
    ] {
        assert!(
            parse(source(&rule(tail)), Limits::default()).is_err(),
            "{tail}"
        );
    }
    for number in ["01", "-01", "+1", "1.2", "1e3", "0x10", "1_0", "-"] {
        let text = doc(&format!("const x: principal = {number};"));
        assert!(parse(source(&text), Limits::default()).is_err(), "{number}");
    }
    assert_eq!(
        code(&rule("all").replace("junco 1", "junco 2")),
        Code::Version
    );
    assert_eq!(code(&(rule("all") + " garbage")), Code::UnexpectedToken);
    let two = doc("rule a { candidate { principal: $p, action: $a, resource: $r }; require all; }
        rule b { candidate { principal: $other, action: $a, resource: $r }; require event { principal == $p }; }");
    assert_eq!(code(&two), Code::UnboundVariable);
    let duplicate = doc(
        "rule a { candidate { principal: $p, action: $a, resource: $r }; require all; }
        rule a { candidate { principal: $p, action: $a, resource: $r }; require all; }",
    );
    assert_eq!(code(&duplicate), Code::DuplicateName);
}

struct BadTag;
impl Resolver<Lock> for BadTag {
    type Error = ResolveError;
    fn vocabulary(&self) -> Vocabulary<'_> {
        LockVocabulary.vocabulary()
    }
    fn resolve(
        &self,
        _: Component,
        _: Literal<'_>,
    ) -> Result<Component3<u32, u32, u32>, Self::Error> {
        Ok(Component3::C0(1))
    }
}

#[test]
fn host_contract_and_resolver_errors_are_not_success_shaped() {
    let text = rule("event { action == action.read }");
    let parsed = parse(source(&text), Limits::default()).unwrap();
    assert!(
        matches!(lower::<Lock, _>(&parsed, &BadTag), Err(LowerError::Frontend(e)) if e.code == Code::Adapter)
    );
    let text = rule("event { action == action.missing }");
    let parsed = parse(source(&text), Limits::default()).unwrap();
    match lower::<Lock, _>(&parsed, &LockVocabulary).unwrap_err() {
        LowerError::Resolver { span, error } => {
            assert_eq!(&text[span.start..span.end], "action.missing");
            assert_eq!(error, ResolveError);
        }
        other => panic!("{other:?}"),
    }
}

struct HostShape<'a>(Vocabulary<'a>);
impl Resolver<Lock> for HostShape<'_> {
    type Error = ResolveError;
    fn vocabulary(&self) -> Vocabulary<'_> {
        self.0
    }
    fn resolve(
        &self,
        _: Component,
        _: Literal<'_>,
    ) -> Result<Component3<u32, u32, u32>, Self::Error> {
        panic!("invalid schema must be rejected before resolving values")
    }
}

#[test]
fn invalid_host_arity_and_coordinate_names_are_rejected() {
    let text = rule("all");
    let parsed = parse(source(&text), Limits::default()).unwrap();
    let native = LockVocabulary.vocabulary();
    let mut duplicate = native.coordinates.to_vec();
    duplicate[2].name = duplicate[0].name;
    let mut keyword = native.coordinates.to_vec();
    keyword[0].name = "event";
    for coordinates in [
        &native.coordinates[..2],
        duplicate.as_slice(),
        keyword.as_slice(),
    ] {
        let host = HostShape(Vocabulary {
            id: "lock/1",
            coordinates,
        });
        assert!(
            matches!(lower::<Lock, _>(&parsed, &host), Err(LowerError::Frontend(e)) if e.code == Code::Adapter)
        );
    }
}

struct DecodedString;
impl Resolver<Flow> for DecodedString {
    type Error = ResolveError;
    fn vocabulary(&self) -> Vocabulary<'_> {
        FlowVocabulary.vocabulary()
    }
    fn resolve(
        &self,
        coordinate: Component,
        literal: Literal<'_>,
    ) -> Result<history_syntax::Component4<u32, u32, u32, u32>, Self::Error> {
        if coordinate == Component(3) {
            assert_eq!(literal, Literal::String("\u{1f600}//\"\\/\x08\x0c\n\r\t"));
            Ok(history_syntax::Component4::C3(42))
        } else {
            FlowVocabulary.resolve(coordinate, literal)
        }
    }
}

#[test]
fn json_escapes_resolve_exactly_without_comment_interpretation() {
    let text = r#"junco 1; schema "flow/1"; policy p {
        const x: label = "\uD83D\uDE00//\"\\\/\b\f\n\r\t";
        rule r { candidate { principal: $p, handle: $v, action: $a, label: x }; require all; }
    }"#;
    let parsed = parse(source(text), Limits::default()).unwrap();
    let typed = lower::<Flow, _>(&parsed, &DecodedString).unwrap();
    assert_eq!(
        typed.entries()[0].rule.head.slots()[3],
        ComponentPattern::Constant(history_syntax::Component4::C3(42))
    );
}

#[test]
fn resource_limits_hold_at_boundaries_and_before_decoding() {
    let text = doc("");
    assert!(
        parse(
            source(&text),
            Limits {
                source_bytes: text.len(),
                tokens: 10,
                ..Limits::default()
            }
        )
        .is_ok()
    );
    for limits in [
        Limits {
            source_bytes: text.len() - 1,
            ..Limits::default()
        },
        Limits {
            tokens: 9,
            ..Limits::default()
        },
        Limits {
            source_bytes: 0,
            ..Limits::default()
        },
        Limits {
            nodes: usize::MAX,
            ..Limits::default()
        },
    ] {
        assert_eq!(parse(source(&text), limits).unwrap_err().code, Code::Limit);
    }
    let text = rule("all");
    assert!(
        parse(
            source(&text),
            Limits {
                nodes: 1,
                rules: 1,
                nesting: 1,
                ..Limits::default()
            }
        )
        .is_ok()
    );
    for limits in [
        Limits {
            nodes: 0,
            ..Limits::default()
        },
        Limits {
            rules: 0,
            ..Limits::default()
        },
        Limits {
            nesting: 0,
            ..Limits::default()
        },
        Limits {
            identifier_bytes: 5,
            ..Limits::default()
        },
        Limits {
            literal_bytes: 7,
            ..Limits::default()
        },
    ] {
        assert_eq!(parse(source(&text), limits).unwrap_err().code, Code::Limit);
    }
    let text = doc("const x: principal = 1;");
    assert!(
        parse(
            source(&text),
            Limits {
                constants: 1,
                ..Limits::default()
            }
        )
        .is_ok()
    );
    assert_eq!(
        parse(
            source(&text),
            Limits {
                constants: 0,
                ..Limits::default()
            }
        )
        .unwrap_err()
        .code,
        Code::Limit
    );
    let text = rule("event { true }");
    assert!(
        parse(
            source(&text),
            Limits {
                nesting: 2,
                ..Limits::default()
            }
        )
        .is_ok()
    );
    assert_eq!(
        parse(
            source(&text),
            Limits {
                nesting: 1,
                ..Limits::default()
            }
        )
        .unwrap_err()
        .code,
        Code::Limit
    );
    let text = rule(&format!("{}all{}", "(".repeat(64), ")".repeat(64)));
    assert_eq!(
        parse(source(&text), Limits::default()).unwrap_err().code,
        Code::Limit
    );
    let text = rule(&format!("{}all", "!".repeat(64)));
    assert_eq!(
        parse(source(&text), Limits::default()).unwrap_err().code,
        Code::Limit
    );
    let text = rule(&vec!["all"; 2000].join(" | "));
    assert!(parse(source(&text), Limits::default()).is_ok());
    // Byte limits precede UTF-8 inspection as well as all allocation.
    assert_eq!(
        parse_bytes(
            SourceId(1),
            b"\xff\xff",
            Limits {
                source_bytes: 1,
                ..Limits::default()
            }
        )
        .unwrap_err()
        .code,
        Code::Limit
    );
}
