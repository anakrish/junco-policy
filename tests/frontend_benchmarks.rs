//! Independent untimed benchmark-port preflights, not latency measurements.
#[path = "../benches/agentdojo/bridge.rs"]
#[allow(dead_code)]
mod bridge;
#[path = "../benches/agentdojo/camel.rs"]
#[allow(dead_code)]
mod camel;
#[path = "../benches/progress.rs"]
#[allow(dead_code)]
mod progress;
#[path = "../benches/resharp/main.rs"]
#[allow(dead_code)]
mod resharp;
#[path = "../benches/smt/main.rs"]
#[allow(dead_code)]
mod smt;
#[path = "../benches/agentdojo/tools.rs"]
#[allow(dead_code)]
mod tools;
#[path = "../benches/validator.rs"]
#[allow(dead_code)]
mod validator;

#[test]
fn validator_fixture_families() {
    validator::textual_preflight();
}
#[test]
fn progress_fixture_families() {
    progress::textual_preflight();
}
#[test]
fn regexlib_all_twenty_corpus_recipes() {
    smt::textual::preflight();
}
#[test]
fn resharp_byte_algebra() {
    resharp::textual_preflight();
}
#[test]
fn camel_native_diagnostics_and_audit_append() {
    camel::textual_preflight();
}
