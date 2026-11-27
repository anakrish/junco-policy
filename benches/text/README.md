# Textual benchmark policies

Junco Text v1 is authoritative for every committed Junco benchmark authoring
workload. `mod.rs` shares typed host resolution and text-only expression builders.
Ordinary policies use files/templates; regex/corpus/depth/alphabet stress cases
generate explicit text. No native policy factory feeds the textual loader.
Existing native DSL fixtures are untimed independent semantic/diagnostic oracles.

| Target | Authoritative source / coverage |
|---|---|
| validator | Terminal prior-edit template (no trailing `all`), duplicate-remove, generated alternating principal/resource depth, optional factors, residual growth, absent witnesses, and an empty rollback policy |
| progress | `progress-prior.junco`, `progress-approval.junco`, all eight approval seed variants |
| smt | `smt/textual.rs` recipes, shared representative data; all 20 regexes / 100 original inclusion instances |
| resharp | `resharp/translate.rs` byte-HIR-to-text and text-only custom algebra; all 40 original workloads |
| agentdojo | `agentdojo/flow.junco`, untrusted/sink and private/peer; live, scripted and event replay all consume the same audited policy |
| fuzz lock_policy / lock / other | `lock.junco`, all seven rules via `textual_benchmarks`; native diagnostic callbacks and claim folding retained |

Parsing and lowering precede every original evaluation or compilation timer.
Compilation groups clone already-lowered source before starting the engine
timer, replacing the old untimed native factory. Evaluation groups retain the
same kernel, caches, history shapes, diagnostic work, grant/append/rollback
behavior, sample sizes, names and calibration. No frontend timing group is
needed to preserve those engine-only boundaries.

`tests/frontend_benchmarks.rs`, benchmark preflights, and the fuzz adapter test
check native equivalence, including original-history resets, empty/singleton/
whole histories, candidate exclusion, byte classes over the open event domain,
generated depth shapes, full native denials/fixes and audited append behavior.
SMT checks mutual language inclusion against each native recipe on the original
declared finite domains. RE# preflights also check each actual haystack.

`history-text::parse_generated` opts into bounded iterative parsing/lowering for
deeper generated corpora; the default language/API limits remain unchanged.
All standard and generated source is still explicit v1 syntax, with no counted
repetition, macro, arbitrary call, or implicit query extension.

The AgentDojo target is an existing async workload driver, not Criterion.
Its additive `--test --noplot` path runs only model-free textual-policy and event
preflights; normal live/script/event modes and timings stay unchanged.
No provider requests or AgentDojo Python execution occur in smoke validation.
The fuzz `other` comparison remains dependent on VeriMon; absence is an error,
not a skip-shaped success. No full performance sessions or new latency claims
are part of this port.
