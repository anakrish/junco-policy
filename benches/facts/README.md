# Facts benchmark policy sources

All committed **Junco** benchmark policies use authoritative Facts source and the
published `history_facts::parse` / `lower` APIs, then the same existing kernel.
`Algebra(String)` in `mod.rs` generates genuine flat textual instructions directly;
it never receives, serializes or wraps a native DSL policy factory.

| Suite | Textual policy coverage |
| --- | --- |
| root `validator` | Terminal prior edit (`All.Test`, no trailing `All`), duplicate removal, empty rollback policy; generated principal/resource alternating depth-32 tails, optional factors, growing residual windows and all absent-witness rule counts |
| root `progress` | Prior edit (`All.Test.All`) and full five-factor release/foreign-approval sequence, all existing seed/preflight variants |
| root `smt` | All 100 inclusion instances / 20 original formulas; all 47 alphabet representatives, classes and original right-nested bounded loops, including 67 |
| root `resharp` | All 40 workloads: 22 popular scan, 8 validation, 10 corpus; standard byte-mode HIR and custom complement/intersection/lookaround-existence constructions emit Facts text |
| root `agentdojo` | The two ordered CaMeL flow obligations (untrusted→sink, private→peer), audit recording and native diagnostic strings/fixes |
| fuzz `lock_policy` | All six prefix lengths and four probes; shared seven-rule lock Facts file |
| fuzz `lock` | All 13 lengths, warm and cold panels and four probes; same Facts file |
| fuzz `other` | Every Junco replay/fuzz/deny/deny-cold panel; same Facts file. Dogwood examples/formulas and Verimon/MFOTL comparisons are unchanged |

Ordinary policies live in `.facts` files here. Synthetic algebra/depth/alphabet
workloads generate textual instructions from their original parameters/formulas,
not from a native AST. The SMT regeneration script emits text-building code;
standard regex translation retains byte classes, inequality-based large classes,
the open event resource domain, edge anchors/boundaries and exact optional-tail
shapes. Unsupported interior look assertions still fail explicitly.

## Timing

Parsing/typechecking/lowering runs outside every existing timed evaluation and
kernel-compilation interval. The three validator compilation groups lower
prototypes before registering Criterion functions and clone source **before**
the existing `Instant`; only existing builder/kernel compilation is measured.
Evaluation groups compile and seed outside timing as before.

No names, sample counts, calibration, event alphabets, histories, cache features,
kernel limits, counts, expected verdicts or append/rollback behavior change.
`LockPolicy::from_sources` retains native owner/stale/reader callback selection
and the incremental diagnostic claim fold. `FlowRule::from_source` retains the
native no-contact explanation/fixes. Default built-in constructors are unchanged.
The fuzz benchmark adapters share the unchanged granted-history and seeded
grant/denial generator/replay loops. Their histories and full denial diagnostics
are compared with the independent, unchanged default native fuzzer/oracle.

AgentDojo is an offline/live replay driver rather than a Criterion harness.
Its additive `--test` accepts Cargo's smoke flags and runs its existing offline
policy/event preflight, with no Python, model provider, credentials or network.
Normal live/scripted/event replay and its timers remain unchanged.
External Python/provider execution and Verimon availability are not implied by
compilation or an offline policy preflight.

`tests/frontend_benchmarks.rs` imports the actual loaders and compares textual
sources with untimed independent native DSL oracles. It covers all fixture
families, all 20 SMT formulas, exact generated operator/optional-tail shapes,
whole-history/empty/singleton distinctions, candidate exclusion, resets and native
diagnostics/audit behavior. Existing per-workload comparison preflights remain.

Use Criterion `--test --noplot` for smoke only. **Smoke results imply no new latency
conclusions.** Historical measurement tables elsewhere predate this port; this
change does not rerun or replace them. Separately timing the frontend would require
new labelled groups, not adding parsing to old engine-only intervals.
