# Binding-cache churn benchmarks

Compare Junco and Dogwood while repeatedly querying fixed working sets at
and above Junco's retained cursor-cache capacity.

```sh
cargo +1.98.1 bench --locked --manifest-path fuzz/Cargo.toml --bench binding_churn
```

VeriMon is not required. To run correctness checks without timing:

```sh
cargo +1.98.1 bench --locked --manifest-path fuzz/Cargo.toml --bench binding_churn -- --test
```

## Workload

A Release requires a Read by the same principal on the same resource, with no
subsequent Edit by that principal on that resource. Junco uses `LockEvent` and a
single generic `CompiledPolicy` rule, not the seven-rule ownership-lock policy.
Dogwood uses the equivalent `since` predicate with leaf slicing enabled.

Histories contain round-robin reads on one resource. Each measured iteration
queries every principal in order, with working sets of 16, 17 or 32 bindings.
The same bindings are revisited on every sweep:

| Bindings | Junco behavior after warm-up |
| ---: | --- |
| 16 | Working set fits the 16 cursor slots; unchanged history needs no replay |
| 17, 32 | Sequential queries evict the next needed cursor, forcing repeated replay |

The rule remains sensitive to a future Edit, so its accepted residual cannot
become the absorbing universal language. Cache misses restart from the root.
Dogwood searches backward and finds every witness near the end of the trace.

Unlike the [refund streams](../refunds/README.md), this benchmark revisits a
fixed set of bindings and isolates a bounded-cache eviction cliff, rather than
issuing exclusively new IDs.

## Timing boundaries

Each iteration times one full binding sweep; throughput counts decisions.
Junco retains its policy and unchanged history across sweeps. Dogwood constructs
and ingests a fresh authorizer outside timing per sweep, because each request
appends to its trace. Both engines' compilation, initial ingestion and teardown
are untimed; event construction is also outside timing.

Committed histories contain 1,025, 16,385 or 65,537 events (`2^k + 1`).
These deliberately select spare-capacity cases, so Dogwood's vector growth
occurs during initial ingestion rather than the timed request sweep. Request
observation and cloning remain timed. These are not full-vector allocation,
cold-start or end-to-end throughput measurements.

Preflights check empty history, principal/resource isolation, Edit invalidation,
Read restoration and two complete sweeps for every measured working set.
All measured candidates grant in both engines, with no Dogwood evaluation errors.
All timestamps remain within the 24-hour policy window.

## Results

Local Criterion means, normalized by the number of decisions in each sweep:

| Committed events | Bindings | Junco per decision | Dogwood per decision | Faster |
| ---: | ---: | ---: | ---: | --- |
| 1,025 | 16 | 0.116 us | 35.84 us | Junco, 308.55x |
| 1,025 | 17 | 12.769 us | 35.99 us | Junco, 2.82x |
| 1,025 | 32 | 12.356 us | 36.33 us | Junco, 2.94x |
| 16,385 | 16 | 0.116 us | 41.16 us | Junco, 356.11x |
| 16,385 | 17 | 200.124 us | 44.59 us | Dogwood, 4.49x |
| 16,385 | 32 | 198.097 us | 38.94 us | Dogwood, 5.09x |
| 65,537 | 16 | 0.117 us | 45.87 us | Junco, 392.17x |
| 65,537 | 17 | 807.000 us | 43.10 us | Dogwood, 18.72x |
| 65,537 | 32 | 787.719 us | 44.14 us | Dogwood, 17.85x |

Junco wins at capacity and at the shortest history, while Dogwood wins
above capacity on longer histories. Above capacity, Junco repeatedly replays
the long history while Dogwood searches only a short suffix. The workload
deliberately favors backward scanning, not arbitrary temporal policies.

Measurements are host-specific, with 10 Criterion samples per case. Dogwood's
large-history estimates were noisy: the 65,537-event/32-binding reported interval
was 1.283--1.554 ms per sweep (40.10--48.57 us per decision). Rerun before using
the ratios as performance claims.
