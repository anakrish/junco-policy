use history_facts::Schema;
use junco_policy::{FlowAction, FlowComponent, FlowEvent};

pub struct FlowSchema;
impl Schema<FlowEvent<u8, u8, u8>> for FlowSchema {
    fn name(&self) -> &str {
        "flow"
    }
    fn field(&self, name: &str) -> Option<usize> {
        match name {
            "principal" => Some(0),
            "handle" => Some(1),
            "action" => Some(2),
            "label" => Some(3),
            _ => None,
        }
    }
    fn constant(&self, name: &str) -> Option<FlowComponent<u8, u8, u8>> {
        Some(match name {
            "action.read" => FlowComponent::Action(FlowAction::Read),
            "action.receive" => FlowComponent::Action(FlowAction::Receive),
            "action.contact" => FlowComponent::Action(FlowAction::Contact),
            "action.declassify" => FlowComponent::Action(FlowAction::Declassify),
            "label.untrusted" => FlowComponent::Label(0),
            "label.external" => FlowComponent::Label(1),
            _ => return None,
        })
    }
    fn diagnostic(&self, name: &str) -> bool {
        name == "flow.taint"
    }
}
