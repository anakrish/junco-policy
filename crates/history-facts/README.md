# Junco Facts

**Rego-inspired, NOT Rego-compatible.** This optional `no_std + alloc` frontend
statically expands declarative definitions into existing `history_syntax::Rule<E>`,
`Head<E>`, `TestExpr<E>` and `RegexExpr<E>`. It adds no evaluator, store, temporal
index or core semantic change.

## API and examples

`parse(text, Limits)` returns a span-preserving borrowed `Module` with inspectable
`package()` and `schema()` headers. `lower::<E>(&module, &schema, Limits)` checks all
definitions, including unused ones, and returns typed `Lowered<E>` obligations in
textual order. Neither stage performs authorization.

The host implements `Schema<E>`: a schema name, field/type-to-coordinate lookup,
qualified vocabulary-to-tagged-`E::Component` lookup, and a registered diagnostic
identity catalog. Unknown names and incorrect tags are errors, never coercions.
Lookups must be deterministic, bounded and preserve the host's component equality.
Two coordinates remain distinct even when their Rust payload types are identical.

```rust
use history_facts::{Limits, Schema, lower, parse};
use history_syntax::Component3;

struct Vocabulary;
impl Schema<(u8, u8, u8)> for Vocabulary {
    fn name(&self) -> &str { "example" }
    fn field(&self, name: &str) -> Option<usize> {
        match name {
            "principal" => Some(0), "action" => Some(1),
            "resource" => Some(2), _ => None,
        }
    }
    fn constant(&self, name: &str) -> Option<Component3<u8, u8, u8>> {
        match name {
            "action.edit" => Some(Component3::C1(1)),
            "action.release" => Some(Component3::C1(2)), _ => None,
        }
    }
    fn diagnostic(&self, name: &str) -> bool { name == "prior.edit" }
}
let text = r#"
language junco.facts.v1;
package example;
schema example;
history edited(p: principal, r: resource) if {
    exists e in history {
        e.principal == p; e.resource == r; e.action == action.edit;
    };
}
policy releases ordered {
    require prior on {principal: p, action: action.release, resource: r}
        if { edited(p, r); } report prior.edit;
}
"#;
let limits = Limits::default();
let module = parse(text, limits)?;
let typed = lower(&module, &Vocabulary, limits)?;
assert_eq!(typed.obligations[0].metadata.name, "example.releases.prior");
# Ok::<(), history_facts::Error>(())
```

`runtime` separately enables `Lowered::compile(Arc<Store<E>>)` using existing
`TracePolicy::new`; `std` separately enables dependencies' standard-library
configuration. Default features are empty. The returned policy's
`decide(&history, &candidate)` is noncommitting and preserves compile/runtime errors.
Record a candidate only after the host successfully performs a granted operation.

Each public `Obligation` pairs a source rule with `Metadata { ordinal, name, report,
span }`. Names are `package.policy.obligation`; ordinals start at zero across all
policy blocks. `compile` uses the registered report identity as denial text with no
fixes. For contextual explanations, consume `into_trace_rules(|metadata| callback)`
and pass the result to `TracePolicy::new`. The factory runs once per obligation;
only the first violated rule's callback runs on a denial. Registration does not
claim to implement host callbacks or witness extraction.

Complete source examples and host vocabulary adapters live in `examples/`:

```sh
cargo run -p history-facts --features runtime,std --example prior_edit
cargo run -p history-facts --features runtime,std --example locks
cargo run -p history-facts --features runtime,std --example flow
```

`prior_edit.facts` is an illustrative release requirement, **not** the built-in lock
policy: release on empty history fails. `locks.facts` implements the complete
seven-rule ownership/freshness/last-reader decision table, with owner-before-stale-
before-reader priority; reads and unowned releases grant. Report keys do not replace
the built-in policy's richer contextual explanations. `flow.facts` implements the
complete single-source/single-sink instance of `FlowRule::no_contact_after_read`,
not a complete information-flow security model. The host must record propagation
as receive events and author separate obligations for additional sink labels.

## Grammar

One module has exactly these headers, then zero or more declarations:

```ebnf
module       = "language" "junco.facts.v1" ";"
               "package" qname ";" "schema" qname ";" { declaration } ;
declaration  = fact | predicate | history | policy ;
fact         = "fact" ident ":" field ":=" qname ";" ;
predicate    = "predicate" ident "(" ident ":" "event"
               { "," parameter } ")" "if" event_body ;
history      = "history" ident "(" [ parameters ] ")" "if" history_body ;
parameter    = ident ":" field ;
parameters   = parameter { "," parameter } ;
policy       = "policy" ident "ordered" "{" { obligation } "}" ;
obligation   = ("require" | "forbid") ident "on" head
               "if" history_body "report" qname ";" ;
head         = "{" [ field ":" term { "," field ":" term } ] "}" ;
term         = ident | qname | "_" ;
event_body   = "{" { event_expr ";" } "}" ;
event_expr   = event_and { "or" event_and } ;
event_and    = event_primary { "and" event_primary } ;
event_primary= ident "." field ("==" | "!=") value
               | ident "(" ident { "," value } ")"
               | "true" | "false" | "(" event_expr ")" ;
history_body = "{" { history_expr ";" } "}" ;
history_expr = history_and { "or" history_and } ;
history_and  = history_unary { "and" history_unary } ;
history_unary= "complement" history_unary | history_primary ;
history_primary
             = ident "(" [ value { "," value } ] ")"
               | "true" | "false" | "empty_history"
               | "(" history_expr ")"
               | "exists" ident "in" "history" event_body
               | "since" ident "in" "history" event_body "unless" event_body ;
value        = ident | qname ;
```

`ident` is ASCII `[A-Za-z_][A-Za-z0-9_]*`, excluding language keywords and `_`.
`qname` consists of nonempty identifier segments separated by dots; vocabulary
constants must contain a dot. Package, schema and report names may be single
segments. `#` starts a comment through end of line. Whitespace is insignificant.
There are no trailing commas or declaration terminators after definition bodies.
Semicolons inside bodies and after reports/facts are mandatory. Unsupported tokens
and trailing garbage are rejected. Event/history sorts are validated by lowering.

Precedence, tightest first: calls/parentheses, comparisons, historical `complement`,
`and`, `or`, then semicolon-separated implicit conjunction. Event and history
conjunctions are different sorts. Empty event bodies are true; empty history bodies
accept every complete history.

### Names, typing and deliberate ambiguity fixes

* Facts, predicates and histories share a single-definition namespace. Policy
  names are unique; obligation names are unique within each policy.
* Forward references are allowed; definitions are acyclic input-only static
  macros. Expansion substitutes only explicit inputs, never caller locals.
* A predicate's first and only event input names its current one-event binder.
  History definitions take coordinate-typed value inputs only.
* A bare **declared fact** in an `on` head is a constant, including forward facts.
  A dotted term is host vocabulary. Any other bare term binds a candidate value.
  Locals cannot reuse fact/definition names: no fact-versus-variable shadowing.
* Head fields are unordered syntactically, restored to event coordinate order.
  Omitted fields and `_` use inaccessible fresh variables. A source variable
  cannot bind two coordinates. Equality never introduces a variable.
* Tail values must be static constants or input variables originating at the head,
  used on their original coordinate. No historical field operands, cross-coordinate
  comparison or historical witness retention.
* `since e ... unless { ... }` **rebinds `e` independently for each later event**.
  It does not retain the setter event. Both bodies can access only their own event
  binder, candidate inputs and facts. A binder cannot shadow a value input.

## Meaning and exact lowering

All operations inspect the **complete original committed history**, without
filtering unrelated events or appending the candidate.

| Text | Existing typed DSL |
| --- | --- |
| `e.field == value` / `!=` | `TestExpr::Atom`, tagged constant or head variable |
| event `and` / `or` | `TestExpr::And` / `Or` |
| history `and` / `or` | `RegexExpr::Intersect` / `Union`, on the same history |
| `true` / `false` in history | `All` / `Empty` |
| `empty_history` | `Epsilon` |
| `complement H` | `Not(H)`, whole-history complement |
| `exists e in history { P; }` | `Concat([All, Test(P), All])` |
| `since e in history { S; } unless { C; }` | `Concat([All, Test(S), Star(Test(neg_event(C)))])` |

`neg_event` is structural Boolean negation (swap true/false, equality/disequality,
and/or), not whole-language complement. An existential or persistence form requires
a committed witness, so both reject empty history. Persistence checks clearing
**strictly after** its chosen setter; an empty suffix is allowed, even when setter
and clear overlap. Another setter can reestablish the condition. Separate
existentials can use different witnesses; they do not introduce a join.

`All` accepts empty and nonempty histories, `Empty` accepts none, `Epsilon` accepts
only empty, and `Test` is exactly one event. The temporal sugars deliberately
surround `Test` with the appropriate full-history context. `complement` flips whole-
history membership, including empty history; it is **not negation-as-failure**.

A matching `require` violates when the history body is false; a matching `forbid`
violates when true. Nonmatching heads are skipped. Source order across policy
blocks is semantic; the first violation wins, otherwise grant. The examples
preserve release versus removal resets and principal/handle/label-local
declassification without dropping off-scope history events.

## Bounds, errors and compatibility limits

Default budgets: 1 MiB source, 100,000 tokens, 4 KiB per name, depth 64,
100,000 syntax work/nodes, 1,024 total declarations (including policy blocks),
1,024 obligations, and 100,000 combined expansion work/DSL nodes. Parsing charges
its recursive syntax work as well as AST nodes; lowering charges validation of
unused definitions, arguments, repeated macro expansion and generated temporal
nodes. Limits are conservative work budgets, not promises to fit that many
instructions in a runtime store. Depth has a hard ceiling of 64 even if the host
raises `Limits::depth`. Source bytes are checked before token allocation. No
expansion is truncated or replaced with a default. Existing runtime allocation,
graph and evaluator limits remain independent; convenience compilation uses the
existing public APIs, not a new budgeting interface.

`Error` contains a stable `ErrorKind`, half-open UTF-8 byte `Span`, explanatory
message and an outermost-first call-site expansion trace. Use these offsets with
the original source to produce line/column diagnostics. Metadata independently
maps rule ordinals to names and complete obligation spans. Frontend failures are
never authorization results; compile and decision errors propagate unchanged.

Design deviations from the proposal: v1 supports a **single explicit module**,
not imports or multi-module qualified definition references; multiple policy blocks
compose in textual order. Literals are **symbolic host vocabulary only**, not
strings/JSON escapes or implicit numeric codecs. This keeps exact host-tagged
values, avoids inventing coercions, and bounds all literal processing. Both are
documented compatibility restrictions, not silent partial support. No Rego
unification (`=`), negation-as-failure (`not`), incremental/unordered definitions,
comprehensions, collections, arithmetic, builtins, arbitrary calls, historical
registers/joins, recursion, general sequence algebra or dynamic loading.

Focused tests compare actual parsed source with independent hand-built existing
DSL rules over bounded exhaustive traces, including head mismatch, tail membership,
Require/Forbid polarity and first violation. Lock/flow decisions are also compared
with the built-in policies and simple original-history reference folds. Cases
cover empty history, candidate exclusion, off-scope resets, re-tainting, overlapping
clear, hygiene/cycles, invalid input and limit boundaries, plus append, fork,
rollback, replacement and foreign-history operational errors.

## Trust boundary

**A parser is not automatically covered by Verus proofs.** Lexing, parsing,
precedence, schema lookups, type/name resolution, macro hygiene, temporal lowering,
ordered assembly and metadata are new unverified trusted components. Differential
tests are evidence, not a proof of textual semantics. The existing proved endpoint
applies to the typed source supplied to it, under the repository's native `Event`
projection, equality and hashing obligations. Schema checking cannot prove those
laws. Diagnostic callbacks remain native host code; registration proves neither
purity, termination nor explanation accuracy.
