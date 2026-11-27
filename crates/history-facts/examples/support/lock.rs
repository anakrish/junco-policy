use history_facts::Schema;
use junco_policy::{Action, LockComponent, LockEvent};

pub struct LockSchema;
impl Schema<LockEvent<u8, u8>> for LockSchema {
    fn name(&self) -> &str {
        "lock"
    }
    fn field(&self, name: &str) -> Option<usize> {
        match name {
            "principal" => Some(0),
            "action" => Some(1),
            "resource" => Some(2),
            _ => None,
        }
    }
    fn constant(&self, name: &str) -> Option<LockComponent<u8, u8>> {
        Some(LockComponent::Action(match name {
            "action.read" => Action::Read,
            "action.edit" => Action::Edit,
            "action.release" => Action::Release,
            "action.remove" => Action::Remove,
            _ => return None,
        }))
    }
    fn diagnostic(&self, name: &str) -> bool {
        matches!(
            name,
            "prior.edit_required" | "lock.owner" | "lock.stale" | "lock.reader"
        )
    }
}
