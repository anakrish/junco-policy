#[path = "../examples/support/mod.rs"]
#[allow(dead_code)]
mod support;

use history_pipeline::{ErrorKind, Limits, Literal, Vocabulary, parse};
use history_syntax::{Component, Component3};
use support::{Lock, LockEvent};

const SCHEMA: &str = "schema Lock(principal, action, resource);";
const SIMPLE: &str = "rule R = Candidate | require History | any | deny \"ok\";";

fn fails(body: &str, kind: ErrorKind) {
    let source = format!("{SCHEMA} {body}");
    let failure = parse::<LockEvent>(&source, &Lock, Limits::default()).unwrap_err();
    assert_eq!(failure.kind, kind, "{body}: {failure}");
    assert!(failure.span.start <= failure.span.end && failure.span.end <= source.len());
    assert!(!failure.message.is_empty());
}

#[test]
fn invalid_inputs_are_rejected_with_spans_instead_of_coercions_or_fallbacks() {
    for (body, kind) in [
        ("let P = Event | where resource == p;", ErrorKind::Variable),
        (
            "let P = (p:principal) { Event | where resource == p };",
            ErrorKind::Variable,
        ),
        (
            "let P = (p:principal) { Event | where principal == p }; rule R = Candidate | require History | exists(P(p)) | deny \"x\";",
            ErrorKind::Variable,
        ),
        (
            "let P = (p:principal) { Event | where principal == p }; let L = (r:resource) { History | exists(P(r)) };",
            ErrorKind::Variable,
        ),
        (
            "let S = Candidate | bind principal=p, resource=p;",
            ErrorKind::Head,
        ),
        (
            "let S = Candidate | bind principal=p | where principal == 1;",
            ErrorKind::Head,
        ),
        (
            "let S = Candidate | where action == \"read\" and action == \"edit\";",
            ErrorKind::Head,
        ),
        (
            "let S = Candidate | where action != \"read\";",
            ErrorKind::Syntax,
        ),
        (
            "let S = Candidate | where action == \"read\" or action == \"edit\";",
            ErrorKind::Syntax,
        ),
        (
            "let P = Event | where unknown == 1;",
            ErrorKind::UnknownName,
        ),
        (
            "let P = Event | where action == \"fly\";",
            ErrorKind::Literal,
        ),
        ("let P = Event | where action == 1;", ErrorKind::Literal),
        (
            "let P = Event | where principal == \"1\";",
            ErrorKind::Literal,
        ),
        (
            "let P = Event | where principal == 18446744073709551616;",
            ErrorKind::Literal,
        ),
        (
            "let P = Event | where principal == 4294967296;",
            ErrorKind::Literal,
        ),
        (
            "let P = Event | where principal == 1.0;",
            ErrorKind::Unsupported,
        ),
        (
            "let P = Event | where principal == null;",
            ErrorKind::Variable,
        ),
        (
            "let P = Event | where action == \"\\u0065dit\";",
            ErrorKind::Literal,
        ),
        ("let P = Event | where action == \"edit;", ErrorKind::Syntax),
        (
            "let L = History | where action == \"read\";",
            ErrorKind::Unsupported,
        ),
        (
            "let L = History | summarize count();",
            ErrorKind::Unsupported,
        ),
        ("let L = History | scan;", ErrorKind::Unsupported),
        ("let L = History | join;", ErrorKind::Unsupported),
        ("let L = History | ago(1);", ErrorKind::Unsupported),
        ("let A = A;", ErrorKind::UnknownName),
        ("let A = B; let B = History | any;", ErrorKind::UnknownName),
        (
            "let A = History | any; let A = History | empty;",
            ErrorKind::Duplicate,
        ),
        ("let principal = History | any;", ErrorKind::Duplicate),
        (
            "let A = (p:principal, p:principal) { Event };",
            ErrorKind::Duplicate,
        ),
        ("let P = (p:principal) { Candidate };", ErrorKind::Kind),
        (
            "let P = Event; rule R = P | require History | any | deny \"x\";",
            ErrorKind::Kind,
        ),
        (
            "let S = Candidate; rule R = S | require S | deny \"x\";",
            ErrorKind::Kind,
        ),
        (
            "let S = Candidate; let L = History | exists(S);",
            ErrorKind::Kind,
        ),
        (
            "let P = Event; let L = History | any | also P;",
            ErrorKind::Kind,
        ),
        (
            "let P = (p:principal) { Event | where principal == p }; let L = History | exists(P);",
            ErrorKind::Kind,
        ),
        (
            "let P = (p:principal) { Event }; let L = History | exists(P());",
            ErrorKind::Syntax,
        ),
        (
            "let P = Event; let L = History | exists(P(1));",
            ErrorKind::Syntax,
        ),
        (
            "rule R = Candidate | require History | any | diagnostic missing;",
            ErrorKind::UnknownName,
        ),
        (
            "rule R = Candidate | require History | any | deny \"x\"; let A = R;",
            ErrorKind::Kind,
        ),
        (
            "rule R = Candidate | require History | any | forbid History | never | deny \"x\";",
            ErrorKind::Syntax,
        ),
        (
            "rule R = Candidate | require History | any | deny \"x\"; garbage",
            ErrorKind::Unsupported,
        ),
    ] {
        fails(body, kind);
    }
    for source in [
        "schema Wrong(principal, action, resource);",
        "schema Lock(action, principal, resource);",
        "schema Lock(principal, action);",
        "schema Lock(principal, action, resource, other);",
    ] {
        assert!(parse::<LockEvent>(source, &Lock, Limits::default()).is_err());
    }
}

#[test]
fn source_token_literal_rule_node_and_nesting_boundaries_are_enforced() {
    let source = format!("{SCHEMA} {SIMPLE}");
    let exact = Limits {
        source_bytes: source.len(),
        rules: 1,
        ..Limits::default()
    };
    assert!(parse::<LockEvent>(&source, &Lock, exact).is_ok());
    assert_eq!(
        parse::<LockEvent>(
            &source,
            &Lock,
            Limits {
                source_bytes: source.len() - 1,
                ..exact
            }
        )
        .unwrap_err()
        .kind,
        ErrorKind::Limit
    );
    assert_eq!(
        parse::<LockEvent>(&source, &Lock, Limits { rules: 0, ..exact })
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
    let two_rules = format!("{source} {}", SIMPLE.replace(" R ", " S "));
    assert_eq!(
        parse::<LockEvent>(
            &two_rules,
            &Lock,
            Limits {
                rules: 1,
                ..Limits::default()
            }
        )
        .unwrap_err()
        .kind,
        ErrorKind::Limit
    );

    assert!(
        parse::<LockEvent>(
            SCHEMA,
            &Lock,
            Limits {
                tokens: 10,
                ..Limits::default()
            }
        )
        .is_ok()
    );
    assert_eq!(
        parse::<LockEvent>(
            SCHEMA,
            &Lock,
            Limits {
                tokens: 9,
                ..Limits::default()
            }
        )
        .unwrap_err()
        .kind,
        ErrorKind::Limit
    );
    assert!(
        parse::<LockEvent>(
            &source,
            &Lock,
            Limits {
                nodes: 6,
                ..Limits::default()
            }
        )
        .is_ok()
    );
    assert_eq!(
        parse::<LockEvent>(
            &source,
            &Lock,
            Limits {
                nodes: 5,
                ..Limits::default()
            }
        )
        .unwrap_err()
        .kind,
        ErrorKind::Limit
    );
    let literal = format!(
        "{SCHEMA} rule R = Candidate | require History | any | deny \"{}\";",
        "x".repeat(16)
    );
    assert!(
        parse::<LockEvent>(
            &literal,
            &Lock,
            Limits {
                literal_bytes: 16,
                ..Limits::default()
            }
        )
        .is_ok()
    );
    assert_eq!(
        parse::<LockEvent>(
            &literal,
            &Lock,
            Limits {
                literal_bytes: 15,
                ..Limits::default()
            }
        )
        .unwrap_err()
        .kind,
        ErrorKind::Limit
    );
    let nested = format!(
        "{SCHEMA} let P = Event | where {}true{};",
        "not(".repeat(70),
        ")".repeat(70)
    );
    assert_eq!(
        parse::<LockEvent>(&nested, &Lock, Limits::default())
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
    let chain = format!(
        "{SCHEMA} let A = History | any {};",
        "| complement ".repeat(64)
    );
    assert_eq!(
        parse::<LockEvent>(&chain, &Lock, Limits::default())
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
    let hard = Limits {
        nesting: 65,
        ..Limits::default()
    };
    assert_eq!(
        parse::<LockEvent>(SCHEMA, &Lock, hard).unwrap_err().kind,
        ErrorKind::Limit
    );
}

#[test]
fn named_static_expansion_is_bounded_even_for_shallow_doubling() {
    let mut source = format!("{SCHEMA} let P0 = Event;");
    for i in 1..15 {
        source.push_str(&format!(
            " let P{i} = Event | where P{} and P{};",
            i - 1,
            i - 1
        ));
    }
    assert_eq!(
        parse::<LockEvent>(&source, &Lock, Limits::default())
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
    let alias_chain = format!(
        "{SCHEMA} let A0 = History | any;{}",
        (1..50)
            .map(|i| format!("let A{i} = A{} | complement;", i - 1))
            .collect::<String>()
    );
    assert_eq!(
        parse::<LockEvent>(&alias_chain, &Lock, Limits::default())
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
}

struct BadHost;
impl Vocabulary<LockEvent> for BadHost {
    fn schema(&self) -> &str {
        "Lock"
    }
    fn fields(&self) -> &[&str] {
        &["principal", "action", "resource"]
    }
    fn constant(&self, _: Component, _: &Literal) -> Option<Component3<u32, u8, u32>> {
        Some(Component3::C0(0))
    }
}

#[test]
fn host_tagging_is_checked_and_strings_are_utf8_with_small_escape_set() {
    let source = format!("{SCHEMA} let P = Event | where action == \"edit\";");
    let failure = parse::<LockEvent>(&source, &BadHost, Limits::default()).unwrap_err();
    assert_eq!(failure.kind, ErrorKind::Schema);
    assert_eq!(&source[failure.span.start..failure.span.end], "\"edit\"");
    let source = format!(
        "{SCHEMA} rule R = Candidate | require History | any | deny \"café\\n\\\"ok\\\"\\\\\" fix \"a\\tb\\r\";"
    );
    let document = parse::<LockEvent>(&source, &Lock, Limits::default()).unwrap();
    assert_eq!(document.rules()[0].diagnostic.message, "café\n\"ok\"\\");
    assert_eq!(document.rules()[0].diagnostic.fixes, ["a\tb\r"]);
}

#[test]
fn explicit_algebra_is_bounded_typed_source_not_a_runtime_stack() {
    let source = |instructions: &str| {
        format!(
            "{SCHEMA} rule R = Candidate | require History | algebra {{ {instructions} }} | deny \"x\";"
        )
    };
    for (instructions, kind) in [
        ("star;", ErrorKind::Syntax),
        ("any; concat 2;", ErrorKind::Syntax),
        ("any; any;", ErrorKind::Syntax),
        ("", ErrorKind::Syntax),
        ("any; concat 184467440737095516160;", ErrorKind::Limit),
        ("any; concat -1;", ErrorKind::Unsupported),
        ("any; concat missing;", ErrorKind::Syntax),
        ("any; join;", ErrorKind::Unsupported),
        (
            "single (Event | where principal == p);",
            ErrorKind::Variable,
        ),
        (
            "single (Event | where any_of(resource == p));",
            ErrorKind::Variable,
        ),
    ] {
        assert_eq!(
            parse::<LockEvent>(&source(instructions), &Lock, Limits::default())
                .unwrap_err()
                .kind,
            kind
        );
    }
    fails("let A = History | algebra { any; };", ErrorKind::Kind);
    let exact = source(&format!("empty;{}", "star;".repeat(511)));
    let document = parse::<LockEvent>(&exact, &Lock, Limits::default()).unwrap();
    drop(document);
    let over = source(&format!("empty;{}", "star;".repeat(512)));
    assert_eq!(
        parse::<LockEvent>(&over, &Lock, Limits::default())
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
    for instruction in ["concat 0;", "choice 0;", "intersection 0;"] {
        assert!(parse::<LockEvent>(&source(instruction), &Lock, Limits::default()).is_ok());
    }
    let predicate = (0..128)
        .map(|i| format!("principal != {i}"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(
        parse::<LockEvent>(
            &source(&format!("single (Event | where all_of({predicate}));")),
            &Lock,
            Limits::default()
        )
        .is_ok()
    );
}
