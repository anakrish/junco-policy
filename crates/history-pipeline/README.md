# KQL-inspired Junco pipelines

`history-pipeline` is a bounded textual frontend, **not Kusto/KQL compatible**.
It has four kinds: candidate selector (`Head<E>` plus exposed bindings), event
predicate (`TestExpr<E>`), whole-history language (`RegexExpr<E>`), and ordered
rule (`Rule<E>` plus diagnostic metadata). There are no tables or new evaluator.

## API and examples

Implement `Vocabulary<E>` for your existing `history_syntax::Event`. The host
provides a schema name, unique field names in coordinate order, and decodes
strings/unsigned decimal integers into tagged `E::Component` constants. Unknown
values return `None`; the frontend checks every decoded constant's coordinate.
No path normalization, identity interning, classification or implicit casts occur.
The host must keep vocabulary methods deterministic and bounded; the frontend
cannot prevent allocations or arbitrary computation inside trusted host Rust.

```rust
use history_pipeline::{Limits, Vocabulary, parse, lower};
use history_syntax::Event;

fn rules<E: Event>(source: &str, vocabulary: &impl Vocabulary<E>)
    -> Result<Vec<history_pipeline::NamedRule<E>>, history_pipeline::Error>
{
    Ok(lower(parse(source, vocabulary, Limits::default())?))
}
```

`parse` returns a privately constructed, typechecked `Document<E>`.
`Document::rules` exposes the typed rules; `lower` transfers them without copying.
With `runtime`, `compile(document, Arc<Store<E>>)` calls the existing
`TracePolicy::new` and returns its `CompileError` unchanged. Its public `decide`
returns `Result<PolicyDecision, HistoryError>`: errors are not grants or denials.
Decision evaluation never appends the candidate. Commit only successful actions
after a grant, using the existing `History` API.

Run the executable host adapter and all three policy examples:

```sh
cargo run --locked -p history-pipeline --example policies
cargo test --locked -p history-pipeline --all-targets --all-features
cargo check --locked -p history-pipeline --no-default-features
```

- [`prior-edit.pipeline`](examples/prior-edit.pipeline) is an illustrative
  Require policy, **not** an additional built-in lock rule.
- [`lock.pipeline`](examples/lock.pipeline) implements all seven built-in lock
  decision rules: foreign owner before freshness before foreign last-reader.
  Releases keep reader claims and stale views; removal resets all three.
- [`flow.pipeline`](examples/flow.pipeline) checks principal/handle-local taint,
  with matching-label declassification and read/receive re-tainting.

The runnable adapter uses tuple events and tagged `Component3`/`Component4`
values, so it is independent of application event constructors. Its lock
diagnostics are static `owner`/`stale`/`reader` messages, not the built-in facade's
candidate-rendered explanatory text. Hosts may register static diagnostics with
`Vocabulary::diagnostic`. To use dynamic native renderers, consume `lower` and
pair each `Rule<E>` with a host `TraceRule` callback; no source calls are allowed.

## Grammar

Case-sensitive ASCII identifiers, `//` comments, whitespace, double-quoted UTF-8
strings (`\"`, `\\`, `\n`, `\r`, `\t` only), and decimal `u64` literals are accepted.
Integers remain literals until the coordinate vocabulary accepts them. Raw
control characters, floats, signs, Unicode escapes and interpolation are rejected.

```ebnf
file       = "schema" Ident "(" fields ")" ";" declaration* ;
declaration = "let" Ident "=" definition ";"
            | "rule" Ident "=" selector "|" mode history "|" diagnostic ";" ;
definition = expression | "(" [parameters] ")" "{" expression "}" ;
parameters = Ident ":" Field { "," Ident ":" Field } ;
expression = candidate | event | history | reference ;
selector   = candidate | reference ;  (* reference must have selector kind *)
candidate  = "Candidate" { "|" ("bind" bindings | "where" equalities) } ;
bindings   = Field "=" Ident { "," Field "=" Ident } ;
equalities = Field "==" Literal { "and" Field "==" Literal } ;
event      = "Event" { "|" "where" predicate } ;
predicate  = conjunction { "or" conjunction } ;
conjunction = unary { "and" unary } ;
unary      = "true" | "false" | Field ("==" | "!=") value
           | reference | "not" "(" predicate ")" | "(" predicate ")"
           | ("all_of" | "any_of") "(" [predicate { "," predicate }] ")" ;
history    = primary { "|" ("also" operand | "either" operand | "complement") } ;
primary    = "History" "|" constructor | reference | "(" history ")" ;
operand    = reference | "(" history ")" ;
constructor = "any" | "empty" | "never"
            | "exists" "(" predicate_arg ")"
            | "active" "(" predicate_arg "," "reset" "=" predicate_arg ")"
            | "algebra" "{" instruction* "}" ;
instruction = ("any" | "empty" | "never" | "star" | "negate") ";"
            | "single" predicate_arg ";"
            | ("concat" | "choice" | "intersection") Integer ";" ;
predicate_arg = reference | "(" event ")" ;
reference  = Ident [ "(" [value { "," value }] ")" ] ;
value      = Literal | Ident ;
mode       = "require" | "forbid" ;
diagnostic = "deny" String [ "fix" String { "," String } ]
           | "diagnostic" Ident ;
```

References are checked against the required kind and exact typed argument list.
Only earlier `let` definitions are referencable; rules are not expressions.
No forward references, recursion, imports, declaration shadowing or duplicate
parameters. Fields and reserved/unsupported operator names cannot name
declarations, parameters or exposed bindings.

Only literal constant conjunctions are legal in candidate `where`. A coordinate
can be bound or restricted once, never both; a binding name belongs to one
coordinate. At most one `bind` stage is allowed. Unspecified coordinates become
inaccessible generated head variables (not DSL wildcards). `Event` can have zero
or multiple `where` stages. **`where` is never legal on committed `History`**, nor
on a named alias as a table filter.

Definitions of predicates and languages may have typed parameters. Parameters
are coordinate identities, even if two coordinates use the same Rust payload
type. They may only resolve to literals or same-coordinate candidate bindings.
Definitions cannot capture a rule's free bindings. Expansion substitutes each
original pattern once, using inaccessible parameter names: argument values are
never re-substituted or captured. Parameterized selectors are rejected because
the MVP candidate head has no parameter-valued restrictions.

## Exact semantics

`exists(P)` lowers to `All · Test(P) · All`.
`active(P, reset=Q)` lowers **exactly** to
`All · Test(P) · Star(Test(not Q))`. The suffix consumes every original event;
it is not a filtered history. A trigger can itself match the reset; resets apply
strictly after that trigger. Unrelated events are consumed, not removed.

`any`, `empty`, and `never` lower to `All`, `Epsilon`, and `Empty`, respectively.
An event predicate remains a one-event `Test`, even `true` or `false`.
`also`/`either` are whole-language intersection/union, left-associative;
witnesses need not correlate. `complement` is whole-language `RegexExpr::Not`.
Predicate `not` applies De Morgan and flips Eq/Neq, without changing consumption.
`all_of` and `any_of` construct n-ary predicate conjunction/disjunction directly,
including the native empty-list identities. They avoid a deep binary chain for
byte-class predicates without changing their open-domain equality semantics.

### Explicit whole-history algebra

For generated workloads and policies outside occurrence/reset sugar, an inline
rule can use a bounded postfix **source expression**, not a scan/evaluator:

```text
schema Lock(principal, action, resource);
rule TerminalEdit = Candidate | bind principal=p, resource=r | where action == "release"
    | require History | algebra {
        any;
        single (Event | where all_of(principal == p, action == "edit", resource == r));
        concat 2;
    } | deny "The final committed event must be a matching edit.";
```

This is exactly `All · Test(P)`, **not** `exists(P)`'s `All · Test(P) · All`.
Instructions construct typed syntax on a parser-owned stack:

| Instruction | DSL construction |
| --- | --- |
| `any;` / `empty;` / `never;` | push All / Epsilon / Empty |
| `single (Event ...);` or `single Predicate(args);` | push Test(predicate) |
| `star;` / `negate;` | wrap the top language in Star / Not |
| `concat n;` / `choice n;` / `intersection n;` | pop the last n languages in source order; push Concat / Union / Intersect |

Zero-operand combinators preserve native identities: concat is epsilon, choice
is empty, intersection is universal. Exactly one language must remain. Operand
underflow, overflow, unknown instructions and trailing garbage are errors.
`single` consumes one original event. `negate` is whole-language complement,
distinct from predicate `not`. No instruction can filter history or access a
runtime table, stack state or historical binding.

The explicit form is available **only inline in rule languages**, not in `let`
definitions; ordinary typed helpers can supply its predicate arguments. This
avoids recursively cloning/substituting deep helper trees. Construction is
iterative with a separate fixed generated-tree depth cap of **512** (counting
predicate depth), while recursive grammar/predicate parsing still respects
`Limits::nesting` and its unchanged hard cap of 64. All ordinary token, byte and
cumulative node budgets still apply. The algebra's pending stack and unused
document rules use existing iterative `Rule::dispose`; transferred DSL trees
retain their native ownership APIs. There is no new evaluator or frontend cache.

A head mismatch skips a rule. Require violates on nonmembership; Forbid violates
on membership. Rules retain textual order and the first violation's diagnostic.
Named helpers do not add rules or reorder declarations.

## Bounds, limitations and trust

| Limit | Default | Hard cap |
| --- | ---: | ---: |
| Source bytes | 65,536 | 262,144 |
| Tokens | 8,192 | 32,768 |
| Raw literal/identifier bytes | 1,024 | 4,096 |
| Parser/generated-tree nesting | 32 | 64 |
| Cumulative construction/expansion nodes | 16,384 | 65,536 |
| Rules | 128 | 512 |

Source bytes are checked **before lexing/allocation**. Lexing borrows token text;
token/literal bounds precede decoded strings or token insertion. Construction
charges a cumulative node budget before cloning named trees, and checks generated
depth before wrapping expressions. Recursive parsing, substitution, negation,
cloning and destruction are bounded by hard nesting limits for ordinary pipelines.
Explicit algebra has the separately documented iterative construction/depth cap.
Flat Boolean and history chains cannot create arbitrarily deep trees. Host diagnostics are also
checked for size after the trusted host returns them. Frontend limits do not
replace the existing compiler/evaluator's resource controls or memory allocator.
All failures return an `ErrorKind`, half-open source byte `Span`, and explanation.

No aggregates, joins, time windows, `scan` state, historical captures, arbitrary
calls, result rows, regex literals, case-insensitive comparisons or runtime
coercion. Unsupported syntax fails rather than being silently approximated.
Parsing/lowering works with `no_std + alloc`; default `std,runtime` adds existing
runtime compilation. No Verus verification is claimed for this frontend:
the lexer, parser, typechecker, static expansion, diagnostic integration and
host vocabulary remain a **new unverified trust boundary**. Core event laws and
compiler/evaluator obligations still apply to successfully lowered typed rules.

### Proposal corrections and assumptions

The proposal's generic rule grammar omitted inline constructors and selectors;
rules accept both inline sources and correctly typed references. Whole-language
grouping was added for `also`/`either` operands; unparenthesized operands are
references, avoiding ambiguous pipeline consumption. Predicate arguments support
the proposed parenthesized `Event` pipeline. Multiple candidate stages are
accepted in either order, but repeated constraints are rejected even if equal.
Parameterized selectors are explicitly rejected (the proposed head grammar
cannot meaningfully use their parameters). Named diagnostics are bounded static
registrations; dynamic rendering is a host-only public-DSL integration, not an
executable source feature. These choices preserve the documented predicate,
language and rule MVP without inventing table semantics.

Parsing, coordinate typechecking and expansion are fused into `parse`, avoiding
an untyped public intermediate or multiple overlapping limit budgets. `lower`
only transfers the already expanded typed rules. Fail-fast errors retain byte
spans rather than aggregating diagnostics or maintaining per-node provenance.
The conservative cumulative defaults are lower than the proposal's suggested
ceilings; configurable hard caps remain explicit.

The focused tests compare source decisions against independently constructed
existing DSL rules over bounded histories for prior-edit, the seven-rule lock
policy and information flow. They cover empty histories, original reset events,
candidate exclusion, first denial, typed hygiene, invalid inputs, wrong host tags,
operational errors, and resource/expansion boundaries.

## Committed benchmark ports

The root validator/progress/SMT/RE# benchmarks and AgentDojo policy use authoritative
pipeline source files or generated instruction templates in `benches/`.
`benches/support/pipelines.rs` generates text directly, never serializes an
existing native policy factory. Generated SMT/RE# templates construct text, not
`history_syntax::RegexExpr`, despite retaining a local `RegexExpr` name for the
template helper. Existing Rust DSL constructions remain only as untimed oracles
and concrete inclusion-counterexample checks.

Fuzz's lock_policy, lock and other comparison targets use its benchmark-only
text adapter; the original generator, default fuzzer and native oracle remain
unchanged. All seven lock rules are injected into `LockPolicy::from_rules` to
retain native diagnostics and incremental claim folds. AgentDojo injects its
two taint rules with `FlowRule::no_contact_after_read_source`, retaining native
diagnostics, audit mode and batch error behavior. Standard regex translation
retains byte mode, boundary lowering and open-domain class semantics (large
disequality classes and full-byte True still accept non-byte Symbol values).

Parsing/typechecking/lowering happens before the existing evaluation timers.
Validator engine compilation still starts after constructing/preparing the typed
source, exactly as before; parsing is excluded from `Instant` intervals, and
cloning/ingestion/rollback stay at their previous boundaries. No benchmark names,
corpus, histories, sample counts, cache features or backend formulas are changed.
AgentDojo is an offline/event/live driver rather than Criterion: `--test` now
runs its existing offline event preflight, without Python, a provider or output
files. Existing live/self-test modes are unchanged.

Criterion `--test --noplot` and compile preflights are correctness checks, not
new performance measurements; they support **no latency conclusions**.
