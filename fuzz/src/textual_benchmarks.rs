//! Pipeline sources for benchmark decisions and generation, retaining native diagnostics.
use super::*;
use history_pipeline::{Diagnostic, Limits, Literal, Vocabulary, lower, parse};
use history_syntax::Component;
use junco_policy::LockComponent;

struct Vocab;
impl Vocabulary<LockEvent<Agent, PooledPath>> for Vocab {
    fn schema(&self) -> &str {
        "Lock"
    }
    fn fields(&self) -> &[&str] {
        &["principal", "action", "resource"]
    }
    fn constant(
        &self,
        field: Component,
        literal: &Literal,
    ) -> Option<LockComponent<Agent, PooledPath>> {
        match (field.0, literal) {
            (0, Literal::Integer(n)) => usize::try_from(*n)
                .ok()
                .map(|n| LockComponent::Principal(Agent(n))),
            (2, Literal::Integer(n)) => usize::try_from(*n)
                .ok()
                .map(|n| LockComponent::Resource(PooledPath(n))),
            (1, Literal::String(s)) => match s.as_str() {
                "read" => Some(Action::Read),
                "edit" => Some(Action::Edit),
                "release" => Some(Action::Release),
                "remove" => Some(Action::Remove),
                _ => None,
            }
            .map(LockComponent::Action),
            _ => None,
        }
    }
    fn diagnostic(&self, name: &str) -> Option<Diagnostic> {
        ["lock_owner", "lock_stale", "lock_reader"]
            .contains(&name)
            .then(|| Diagnostic {
                message: name.into(),
                fixes: vec![],
            })
    }
}

/// Parses the authoritative seven-rule text outside evaluation timing.
/// Native diagnostic callbacks and the incremental claim fold are retained.
pub fn policy(
    store: Arc<Store<LockEvent<Agent, PooledPath>>>,
) -> Result<LockPolicy<Agent, PooledPath>, junco_core::CompileError> {
    let rules = lower(
        parse(
            include_str!("../../crates/history-pipeline/examples/lock.pipeline"),
            &Vocab,
            Limits::default(),
        )
        .expect("committed lock benchmark text parses"),
    )
    .into_iter()
    .map(|item| item.rule)
    .collect::<Vec<_>>();
    LockPolicy::from_rules(store, rules.try_into().expect("seven textual lock rules"))
}

/// Generates exactly the original granted corpus with a textual policy. The
/// unchanged native policy is used only as an untimed independent diagnostic oracle.
pub fn granted_history(
    data: &[u8],
    length: usize,
) -> Result<History<LockEvent<Agent, PooledPath>>, PolicyError> {
    let mut generator = TraceGenerator::new(data);
    let store = Arc::new(Store::new()?);
    let mut textual = policy(store.clone())?;
    let mut oracle = LockPolicy::new(store.clone())?;
    let mut history = History::new(store)?;
    while history.len() < length {
        let Some(candidate) = generator.next_candidate() else {
            panic!(
                "entropy exhausted after {} of {length} granted events",
                history.len()
            );
        };
        let decision = textual.decide(&history, &candidate.event)?;
        assert_eq!(
            decision,
            oracle.decide(&history, &candidate.event)?,
            "text/native diagnostics"
        );
        if matches!(decision, PolicyDecision::Grant) {
            history.push(candidate.event)?;
            generator.record_grant(&candidate);
        }
    }
    Ok(history)
}

/// Replays seeded candidates through the textual policy without changing generation.
pub fn validate_trace(data: &[u8]) -> Result<ValidatedTrace, PolicyError> {
    let mut generator = TraceGenerator::new(data);
    let store = Arc::new(Store::new()?);
    let mut textual = policy(store.clone())?;
    let mut oracle = LockPolicy::new(store.clone())?;
    let mut trace = ValidatedTrace::new(store)?;
    for _ in 0..generator.step_budget() {
        let Some(candidate) = generator.next_candidate() else {
            break;
        };
        let decision = textual.decide(&trace.history, &candidate.event)?;
        assert_eq!(
            decision,
            oracle.decide(&trace.history, &candidate.event)?,
            "text/native diagnostics"
        );
        match decision {
            PolicyDecision::Grant => {
                trace.history.push(candidate.event)?;
                generator.record_grant(&candidate);
            }
            PolicyDecision::Deny {
                failed_precondition,
                ..
            } => trace.denials.push(DeniedCandidate {
                granted_prefix_len: trace.history.len(),
                event: candidate.event,
                failed_precondition,
            }),
        }
    }
    Ok(trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seeded_corpora_and_diagnostics_are_unchanged() {
        let bytes = entropy(DETERMINISTIC_SEED, SEEDED_TRACE_COUNT * BYTES_PER_TRACE);
        for chunk in bytes.chunks(BYTES_PER_TRACE) {
            assert_eq!(
                validate_trace(chunk).unwrap(),
                super::super::validate_trace(chunk).unwrap()
            );
        }
        let bytes = entropy(DETERMINISTIC_SEED, 128 * BYTES_PER_EVENT);
        assert_eq!(
            granted_history(&bytes, 128).unwrap(),
            super::super::granted_history(&bytes, 128).unwrap()
        );
    }
}
