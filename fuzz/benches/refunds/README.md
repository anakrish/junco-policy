# Refund-stream benchmarks

Compare Junco and Dogwood decision latency for new approved refunds following
abandoned transactions.

```sh
cargo +1.98.1 bench --locked --manifest-path fuzz/Cargo.toml --bench refunds
```

VeriMon is not required. To run correctness checks without timing:

```sh
cargo +1.98.1 bench --locked --manifest-path fuzz/Cargo.toml --bench refunds -- --test
```

## Workload

A refund requires an earlier approval for its ID. Junco uses native
`(action, refund_id)` events and `CompiledPolicy`; Dogwood uses a fixed cashier,
refund resources, and `InMemoryTemporalEngine::new().slice_leaves()`.
The rule allows repeat refunds and approvals do not expire within these traces;
it is not a complete payment policy.

Each `refund_stream` iteration:

1. Ingests an initial history of approvals for unrelated IDs.
2. Queries 0 or 16 unapproved refunds once. These aborted IDs are never approved
   or revisited within the stream.
3. Processes 32 new IDs. For each, append an approval, time the refund decision,
   then commit the successful refund.

Both engines are retained through the 32 new refunds. Junco also retains its
compiled policy across iterations; Dogwood constructs one authorizer per stream,
not per decision. Each iteration starts a fresh bounded history, and new refund
IDs remain distinct across iterations. Every timed refund must grant; Dogwood
evaluation errors fail the benchmark.

The aborted bindings initially fill Junco's 16 cursor slots, but are evicted as
new refunds arrive. All are displaced after 16 new decisions. The zero-aborted
control distinguishes initial cache occupancy from cold-binding replay: an
unseen refund ID needs replay even without abandoned entries. Dogwood can find
its recent approval with a short backward search.

## Timing boundaries

Only the 32 new refund decisions contribute to elapsed time and throughput.
Compilation, initial ingestion, aborted decisions, approvals, successful-refund
commits, event construction and teardown are excluded. This measures decision
latency, not cold-start cost or end-to-end payment throughput.

Initial histories contain 1,025, 16,385 or 65,537 committed events (`2^k + 1`).
Each stream adds 64 committed events. These sizes deliberately leave spare
capacity in Dogwood's history vector after untimed ingestion. Request observation,
cloning and any decision-time allocation are still timed, but these cases do not
measure full-vector growth boundaries. Results do not generalize to histories
whose vectors are full. All timestamps remain within the 24-hour policy window.

Preflights check empty history, refund-ID isolation, denial followed by approval,
permanent approval, and two complete streams for every case.

## Results

Local Criterion means, normalized by the 32 granted decisions per stream:

| Initial events | Aborted refunds | Junco per refund | Dogwood per refund | Faster |
| ---: | ---: | ---: | ---: | --- |
| 1,025 | 0 | 15.84 us | 36.07 us | Junco, 2.28x |
| 1,025 | 16 | 15.87 us | 36.83 us | Junco, 2.32x |
| 16,385 | 0 | 243.47 us | 37.62 us | Dogwood, 6.47x |
| 16,385 | 16 | 249.84 us | 34.72 us | Dogwood, 7.20x |
| 65,537 | 0 | 1.100 ms | 41.34 us | Dogwood, 26.61x |
| 65,537 | 16 | 1.066 ms | 39.24 us | Dogwood, 27.16x |

Similar Junco times with zero and sixteen aborted refunds indicate that new
bindings' cold replay, not permanently occupied slots, drives the observed
scaling. This workload favors recent-witness lookup; it does not establish an
overall winner across authorization workloads.

Measurements are host-specific, with 10 Criterion samples per case. Dogwood's
large-history estimates were noisy: the 65,537-event/16-aborted time interval was
1.142--1.427 ms for all 32 decisions (35.70--44.59 us per refund). Rerun before
using the ratios as performance claims.
