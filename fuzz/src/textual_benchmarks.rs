//! Facts source adapter for committed benchmarks only. The default fuzzer and
//! native no-surprise oracle remain unchanged.

#[path = "../../benches/facts/mod.rs"]
mod facts;

use crate::{Agent, PooledPath};
use history_semantics::PolicyError;
use history_store::{History, Store};
use junco_core::CompileError;
use junco_policy::{LockEvent, LockPolicy};
use std::sync::Arc;

/// Parse/typecheck/lower the shared authoritative lock Facts source, then compile
/// it with the existing native lock diagnostics and context fold.
/// Call before benchmark timers.
pub fn policy(
    store: Arc<Store<LockEvent<Agent, PooledPath>>>,
) -> Result<LockPolicy<Agent, PooledPath>, CompileError> {
    let sources = facts::lock_sources(&facts::LockSchema(
        |id| Agent(id as usize),
        |id| PooledPath(id as usize),
    ));
    LockPolicy::from_sources(store, sources)
}

/// Generate the identical policy-legal corpus using the textual benchmark table.
/// Uses the unchanged generator/replay loop; the old native entry point is still
/// available as an untimed independent oracle.
pub fn granted_history(
    data: &[u8],
    length: usize,
) -> Result<History<LockEvent<Agent, PooledPath>>, PolicyError> {
    let store = Arc::new(Store::new()?);
    let policy = policy(store.clone())?;
    crate::granted_history_with_policy(data, length, store, policy)
}

/// Generate the identical granted/denied benchmark corpus with Facts sources.
/// The default native trace validator remains an independent oracle.
pub fn validate_trace(data: &[u8]) -> Result<crate::ValidatedTrace, PolicyError> {
    let store = Arc::new(Store::new()?);
    let policy = policy(store.clone())?;
    crate::validate_trace_with_policy(data, store, policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn textual_corpus_matches_native_generator_and_diagnostics() {
        let data = crate::entropy(crate::DETERMINISTIC_SEED, 4 * crate::BYTES_PER_TRACE);
        for bytes in data.chunks(crate::BYTES_PER_TRACE).chain([&[][..]]) {
            let text = validate_trace(bytes).unwrap();
            let native = crate::validate_trace(bytes).unwrap();
            assert_eq!(text.history.as_slice(), native.history.as_slice());
            assert_eq!(text.denials, native.denials);
        }
        let data = crate::entropy(crate::DETERMINISTIC_SEED, 256 * crate::BYTES_PER_EVENT);
        let text = granted_history(&data, 32).unwrap();
        let native = crate::granted_history(&data, 32).unwrap();
        assert_eq!(text.as_slice(), native.as_slice());
    }
}
