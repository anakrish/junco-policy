# Junco Text v1

`history-text` is a bounded, typed frontend to `history_syntax`, not an evaluator.
It supports `no_std + alloc` without default features. `runtime` adds a convenience
compiler using existing `TracePolicy`; `std` and `cache` are separate opt-ins.

```text
junco 1;
schema "lock/1";
policy release_checks {
  rule prior_edit {
    candidate { principal: $p, action: action.release, resource: $r };
    require all >> event {
      principal == $p and action == action.edit and resource == $r
    } >> all;
  }
}
```

Call `parse(Source { id: SourceId(1), text }, Limits::default())`, then
`lower::<E, _>(&parsed, &resolver)`. `parse_bytes` also checks UTF-8.
`Resolver<E>` supplies an exact schema identifier, coordinate names in native
order, nominal domains, accepted literal forms, and immutable symbol/literal
resolution into tagged `E::Component` values. Unknown symbols and out-of-range
values must return host errors; every returned tag is checked. Integer spelling
is passed intact, including a possible minus sign; there is no numeric ID
convention, coercion, normalization, filesystem lookup, import, or network loading.
`TypedPolicy::entries` exposes ordered `Rule<E>` values and `RuleInfo` provenance;
`into_entries` supports existing flattening, validators and policy compilers.

With `runtime`, `compile(typed, store, renderer)` returns the existing
`TracePolicy<E>`. The renderer receives rule metadata and the candidate.
Compilation errors retain `CompileError` and the document span (the engine does
not expose a failing index). Evaluation retains `Result<PolicyDecision,
HistoryError>`. Errors are never converted into mismatches or denials.
Compilation may intern constants before failure; codebook rollback is not promised.

Run the complete prior-edit, owner/freshness and information-flow examples:

```sh
cargo run --locked -p history-text --features runtime --example policies
```

## Grammar and semantics

```text
document = junco 1 ; schema STRING ; policy NAME { const* rule* } EOF
const    = const NAME : COORD = VALUE ;
rule     = rule NAME { candidate HEAD ; (require|forbid) HISTORY ; }
HEAD     = { COORD : TERM (, COORD : TERM)* [,] }
TERM     = $NAME | COORD.SYMBOL | STRING | INTEGER | true | false | ALIAS
VALUE    = COORD.SYMBOL | STRING | INTEGER | true | false
HISTORY  = all | empty | epsilon | event { PREDICATE } | ( HISTORY )
         | HISTORY * | ! HISTORY | HISTORY >> HISTORY
         | HISTORY & HISTORY | HISTORY | HISTORY
PREDICATE = true | false | COORD (==|!=) TERM | ( PREDICATE )
          | PREDICATE and PREDICATE | PREDICATE or PREDICATE
```

The last history alternative uses the literal union operator `|`. Highest to
lowest precedence: primary, postfix `*`, prefix `!`, `>>`, `&`, `|`.
Predicate `and` binds tighter than `or`. Prefix complement is right associative;
infix chains are ordered n-ary constructors, preserving explicit parentheses.
`!event { true }*` means `!(event { true }*)`. Repeated `R**` is rejected.
There is no implicit concatenation or substring search.

`all` accepts every complete history, `empty` none, `epsilon` only empty,
and `event { P }` exactly one event. `!` complements the whole history language,
not an event predicate. `event { false }*` accepts only empty histories.
These preserve every native constructor's semantics; empty n-ary identities
are spelled `true`, `false`, `all`, `empty`, or `epsilon`, not empty operand lists.

Heads must name every coordinate once, in any order; lowering restores native
order. Variables bind only the candidate and may be used only at their binding
coordinate in that rule. Unused variables are legal wildcard bindings. Aliases
are coordinate-typed, precede all rules, and cannot refer to other aliases.
Rule and alias names are unique in their respective namespaces.

Rules inspect the **complete original committed history**, oldest first.
The candidate is **never appended** during decisions. Nonmatching heads skip.
`require` violates on rejection; `forbid` violates on acceptance. The first
violation in source order is reported; satisfaction is not an early grant.

Identifiers are ASCII `[A-Za-z][A-Za-z0-9_]*`, case-sensitive. Grammar keywords
are reserved except after `.`. `$` must immediately precede its name.
Whitespace is ASCII space/tab/CR/LF; `//` comments end at CR or LF.
Strings use JSON escapes, including checked UTF-16 surrogate pairs, without
normalization. Raw controls, BOM, malformed escapes and invalid UTF-8 fail.
Integers are `-?(0|[1-9][0-9]*)`; no plus, leading zeroes, decimal points,
exponents, or overflow/truncation in the frontend. The host checks domain range.
No head wildcards, functions, predicate `not`, captures, query windows,
macros, imports, `+`, `?`, or counted repetition are supported.

## Diagnostics, bounds and trust

Diagnostics carry a stable `Code`, half-open source byte `Span`, static message,
and optional related declaration span. Resolver failures retain their concrete
error and source span. `Span::location` derives one-based scalar columns and
CRLF-aware lines without a line table. Success consumes EOF; no partial policy
is returned. Rule metadata retains head-field, atom and operator expression
ranges, not a normalized engine-node-to-text map or history witness.

Ordinary `parse` limits default to, and cannot exceed: 1 MiB source, 65,536 tokens, 128-byte
identifiers, 4096-byte raw/decoded literals, nesting/tree height 64, 32,768
expression nodes, 256 rules, 1024 constants. All can be lowered, including to
zero. Source is checked before allocation. Tokens and names borrow source;
strings are validated and counted before decoding. Collections use fallible
reservation. An arena and explicit parsing/lowering work stacks bound construction
both syntactically and by emitted tree height. Infix chains do not become deep
binary trees. There are no expansions or shared expression references; emitted
node and edge counts are bounded by parsed nodes/tokens. Names and spans copied
during lowering are bounded by those same limits. No independent wall-clock,
exact heap-capacity, runtime graph, or host callback budget is promised.

Existing DSL `Box` constructors and runtime APIs can abort on allocator OOM;
not every allocation failure is recoverable on stable Rust. Host resolvers and
renderers remain trusted application code, not bounded computations supplied by
text. Native event laws (stable projection/equality/hash and event-view laws)
remain host obligations; checking coordinate tags does not establish them.

**The lexer, parser, schema adapter and text-to-DSL lowering are not Verus
verified.** Existing proofs begin at the produced typed source under their
documented native-event obligations. Differential tests provide regression
evidence, not a parser correctness proof. Text version 1 is independent of
portable wire-format version 9. Serialization, round-tripping, rich owner-name
explanations, propagation of receive events, and other deferred language
features are caller responsibilities.

### Generated benchmark corpora

`parse_generated(source, Limits::generated())` is an explicit opt-in to a
512-level nesting/tree ceiling and 1024 rules. All other ceilings and all v1
syntax/semantics stay unchanged; ordinary `parse` still rejects larger limits.
This covers the committed SMT nested optional-repeat corpus without flattening
alternating operators or changing regex meaning. Both predicates and history
expressions are parsed and lowered iteratively. Dropping a `TypedPolicy`, or
completed entries on a lowering failure, uses the existing iterative
`Rule::dispose`; consumers taking ownership of raw DSL rules retain the DSL's
normal disposal obligations. Host callbacks and engine allocation limits remain
independent. These larger bounds do not add counted repetition, macros, queries
or parser proof claims.

The root/fuzz benchmark ports use benchmark-local typed vocabularies and
authoritative policy files or generated explicit text. Native DSL factories
remain only as untimed independent semantic/diagnostic oracles. Parsing and
lowering are outside the original kernel compilation/evaluation timers;
Criterion `--test` preflights make no latency claims.
