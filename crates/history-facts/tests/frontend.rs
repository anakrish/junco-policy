#[path = "../examples/support/lock.rs"]
mod lock;
use history_facts::{ErrorKind as K, Limits, Schema, lower, parse};
use junco_policy::{LockComponent, LockEvent};

const HEADER: &str = "language junco.facts.v1; package tests; schema lock;";

fn resolve(text: &str) -> Result<history_facts::Lowered<LockEvent<u8, u8>>, history_facts::Error> {
    let module = parse(text, Limits::default())?;
    lower(&module, &lock::LockSchema, Limits::default())
}

#[test]
fn unsafe_and_unsupported_inputs_have_precise_errors() {
    let cases = [
        (
            "policy x ordered { require r on {principal: p} if { exists e in history { e.resource == p; }; } report lock.owner; }",
            K::Type,
            "p",
        ),
        (
            "history h() if { exists e in history { e.principal == missing; }; }",
            K::Scope,
            "missing",
        ),
        (
            "predicate q(e: event, p: principal) if { e.resource == p; }",
            K::Type,
            "p",
        ),
        (
            "history h() if { exists e in history { z.action == action.edit; }; }",
            K::Scope,
            "z.action",
        ),
        (
            "history h() if { exists e in history { e.action == action.unknown; }; }",
            K::Unknown,
            "action.unknown",
        ),
        (
            "policy x ordered { forbid r on {no_field: x} if {} report lock.owner; }",
            K::Unknown,
            "no_field",
        ),
        (
            "policy x ordered { forbid r on {principal: x, resource: x} if {} report lock.owner; }",
            K::Type,
            "x",
        ),
        (
            "policy x ordered { forbid r on {action: action.edit, action: action.read} if {} report lock.owner; }",
            K::Duplicate,
            "action",
        ),
        (
            "policy x ordered { forbid r on {} if {} report unknown.report; }",
            K::Unknown,
            "unknown.report",
        ),
        (
            "history h() if { complement (exists e in history { true; }); } garbage",
            K::Syntax,
            "",
        ),
        (
            "history h() if { exists e in history { e.action = action.read; }; }",
            K::Syntax,
            "=",
        ),
        (
            "history h() if { exists e in history { e.action := action.read; }; }",
            K::Syntax,
            ":=",
        ),
        ("history h() if { not true; }", K::Syntax, "not"),
        (
            "history h() if { exists e in history { complement true; }; }",
            K::Type,
            "complement true",
        ),
        (
            "history h() if { e.action == action.read; }",
            K::Type,
            "e.action == action.read",
        ),
        ("history h(e: event) if {}", K::Type, "h"),
        ("predicate q(p: principal) if {}", K::Type, "q"),
        ("fact f: action := \"read\";", K::Syntax, "\""),
        ("fact f: action := action..read;", K::Syntax, "action..read"),
        ("history h() if { builtin(); }", K::Unknown, "builtin"),
        (
            "history h() if { exists e in history { true; }; exists z in history { e.action == action.read; }; }",
            K::Scope,
            "e.action",
        ),
        (
            "history h(p: principal) if { since p in history { true; } unless { true; }; }",
            K::Scope,
            "p",
        ),
    ];
    for (body, kind, fragment) in cases {
        let source = format!("{HEADER} {body}");
        let error = resolve(&source).unwrap_err();
        assert_eq!(error.kind, kind, "{body}: {error}");
        assert!(source.is_char_boundary(error.span.start));
        assert!(source.is_char_boundary(error.span.end));
        assert!(
            source[error.span.start..error.span.end].contains(fragment),
            "{body}: {error}"
        );
    }
}

#[test]
fn forward_names_are_acyclic_and_do_not_capture_caller_variables() {
    let valid = format!("{HEADER}
        history outer(p: principal) if {{ inner(p); }}
        history inner(q: principal) if {{ exists z in history {{ z.principal == q; }}; }}
        policy x ordered {{ require r on {{principal: caller}} if {{ outer(caller); }} report lock.owner; }}");
    assert!(resolve(&valid).is_ok());
    let invalid = valid.replace("z.principal == q", "z.principal == caller");
    let error = resolve(&invalid).unwrap_err();
    assert_eq!(error.kind, K::Scope);
    assert!(!error.expansion.is_empty());
    let cycle = format!("{HEADER} history a() if {{ b(); }} history b() if {{ a(); }}");
    let error = resolve(&cycle).unwrap_err();
    assert_eq!(error.kind, K::Cycle);
    assert!(error.expansion.len() >= 2);
    let invalid_unused = format!("{HEADER} history unused() if {{ typo(); }}");
    assert_eq!(resolve(&invalid_unused).unwrap_err().kind, K::Unknown);
}

#[test]
fn constants_and_variables_in_heads_are_unambiguous() {
    let source = format!(
        "{HEADER}
        policy x ordered {{ forbid r on {{action: operation, resource: _}}
            if {{ true; }} report lock.owner; }}
        fact operation: action := action.edit;"
    );
    let lowered = resolve(&source).unwrap();
    assert!(matches!(
        lowered.obligations[0].rule.head.slots()[1],
        history_syntax::ComponentPattern::Constant(LockComponent::Action(
            junco_policy::Action::Edit
        ))
    ));
    let wrong = source.replace("action: operation", "principal: operation");
    assert_eq!(resolve(&wrong).unwrap_err().kind, K::Type);
    let collision = format!(
        "{HEADER} fact f: action := action.edit;
        history h(f: action) if {{ true; }}"
    );
    assert_eq!(resolve(&collision).unwrap_err().kind, K::Duplicate);
    let duplicate = format!("{HEADER} history h() if {{}} history h() if {{}}");
    assert_eq!(resolve(&duplicate).unwrap_err().kind, K::Duplicate);
    let wrong_arg = format!(
        "{HEADER} history h(p: principal) if {{ true; }}
        policy x ordered {{ forbid r on {{resource: r}} if {{ h(r); }} report lock.owner; }}"
    );
    assert_eq!(resolve(&wrong_arg).unwrap_err().kind, K::Type);
}

#[test]
fn host_schema_tags_and_arity_are_checked_before_emitting_rules() {
    struct BadSchema(bool);
    impl Schema<LockEvent<u8, u8>> for BadSchema {
        fn name(&self) -> &str {
            "lock"
        }
        fn field(&self, _: &str) -> Option<usize> {
            Some(if self.0 { 8 } else { 0 })
        }
        fn constant(&self, _: &str) -> Option<LockComponent<u8, u8>> {
            Some(LockComponent::Resource(1))
        }
        fn diagnostic(&self, _: &str) -> bool {
            true
        }
    }
    let source = format!("{HEADER} fact f: principal := principal.one;");
    let module = parse(&source, Limits::default()).unwrap();
    for schema in [BadSchema(false), BadSchema(true)] {
        assert_eq!(
            lower(&module, &schema, Limits::default()).unwrap_err().kind,
            K::Type
        );
    }
    let wrong_schema = HEADER.replace("schema lock", "schema unknown");
    assert_eq!(resolve(&wrong_schema).unwrap_err().kind, K::Unknown);
}

#[test]
fn resource_boundaries_reject_instead_of_truncating() {
    let exact_bytes = Limits {
        source_bytes: HEADER.len(),
        ..Limits::default()
    };
    assert!(parse(HEADER, exact_bytes).is_ok());
    assert_eq!(
        parse(
            HEADER,
            Limits {
                source_bytes: HEADER.len() - 1,
                ..exact_bytes
            }
        )
        .unwrap_err()
        .kind,
        K::Limit
    );
    assert!(
        parse(
            HEADER,
            Limits {
                tokens: 9,
                ..Limits::default()
            }
        )
        .is_ok()
    );
    assert_eq!(
        parse(
            HEADER,
            Limits {
                tokens: 8,
                ..Limits::default()
            }
        )
        .unwrap_err()
        .kind,
        K::Limit
    );
    let longest = "junco.facts.v1".len();
    assert!(
        parse(
            HEADER,
            Limits {
                lexeme_bytes: longest,
                ..Limits::default()
            }
        )
        .is_ok()
    );
    assert_eq!(
        parse(
            HEADER,
            Limits {
                lexeme_bytes: longest - 1,
                ..Limits::default()
            }
        )
        .unwrap_err()
        .kind,
        K::Limit
    );
    let source =
        format!("{HEADER} policy x ordered {{ require r on {{}} if {{}} report lock.owner; }}");
    let exact = Limits {
        nodes: 1,
        definitions: 1,
        rules: 1,
        depth: 1,
        ..Limits::default()
    };
    let module = parse(&source, exact).unwrap();
    assert!(
        lower(
            &module,
            &lock::LockSchema,
            Limits {
                expansion: 2,
                ..exact
            }
        )
        .is_ok()
    );
    assert_eq!(
        lower(
            &module,
            &lock::LockSchema,
            Limits {
                expansion: 1,
                ..exact
            }
        )
        .unwrap_err()
        .kind,
        K::Limit
    );
    for limits in [
        Limits { nodes: 0, ..exact },
        Limits {
            definitions: 0,
            ..exact
        },
        Limits { rules: 0, ..exact },
        Limits { depth: 0, ..exact },
    ] {
        assert_eq!(parse(&source, limits).unwrap_err().kind, K::Limit);
    }
    let deep = format!(
        "{HEADER} history h() if {{ {}true{}; }}",
        "(".repeat(65),
        ")".repeat(65)
    );
    assert_eq!(
        parse(
            &deep,
            Limits {
                depth: usize::MAX,
                ..Limits::default()
            }
        )
        .unwrap_err()
        .kind,
        K::Limit
    );
    let fanout = format!(
        "{HEADER}
        history a() if {{ b(); b(); }}
        history b() if {{ c(); c(); }}
        history c() if {{ true; }}"
    );
    let module = parse(&fanout, Limits::default()).unwrap();
    assert_eq!(
        lower(
            &module,
            &lock::LockSchema,
            Limits {
                expansion: 8,
                ..Limits::default()
            }
        )
        .unwrap_err()
        .kind,
        K::Limit
    );
    let unicode = format!("{HEADER} é");
    let error = parse(&unicode, Limits::default()).unwrap_err();
    assert_eq!(&unicode[error.span.start..error.span.end], "é");
}
