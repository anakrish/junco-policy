use history_pipeline::{Diagnostic, Literal, Vocabulary};
use history_syntax::{Component, Component3, Component4};

pub type LockEvent = (u32, u8, u32);
pub type FlowEvent = (u32, u32, u8, u8);
pub const READ: u8 = 0;
pub const EDIT: u8 = 1;
pub const RELEASE: u8 = 2;
pub const REMOVE: u8 = 3;
pub const RECEIVE: u8 = 4;
pub const CONTACT: u8 = 5;
pub const DECLASSIFY: u8 = 6;

pub struct Lock;
pub struct Flow;

fn action(literal: &Literal) -> Option<u8> {
    let Literal::String(name) = literal else {
        return None;
    };
    match name.as_str() {
        "read" => Some(READ),
        "edit" => Some(EDIT),
        "release" => Some(RELEASE),
        "remove" => Some(REMOVE),
        "receive" => Some(RECEIVE),
        "contact" => Some(CONTACT),
        "declassify" => Some(DECLASSIFY),
        _ => None,
    }
}

fn number(literal: &Literal) -> Option<u32> {
    let Literal::Integer(value) = literal else {
        return None;
    };
    u32::try_from(*value).ok()
}

impl Vocabulary<LockEvent> for Lock {
    fn schema(&self) -> &str {
        "Lock"
    }
    fn fields(&self) -> &[&str] {
        &["principal", "action", "resource"]
    }
    fn constant(&self, field: Component, literal: &Literal) -> Option<Component3<u32, u8, u32>> {
        match field.0 {
            0 => number(literal).map(Component3::C0),
            1 => action(literal).filter(|a| *a <= REMOVE).map(Component3::C1),
            2 => number(literal).map(Component3::C2),
            _ => None,
        }
    }
    fn diagnostic(&self, name: &str) -> Option<Diagnostic> {
        let message = match name {
            "lock_owner" => "owner",
            "lock_stale" => "stale",
            "lock_reader" => "reader",
            _ => return None,
        };
        Some(Diagnostic {
            message: message.into(),
            fixes: if name == "lock_stale" {
                vec!["read".into()]
            } else {
                vec![]
            },
        })
    }
}

impl Vocabulary<FlowEvent> for Flow {
    fn schema(&self) -> &str {
        "Flow"
    }
    fn fields(&self) -> &[&str] {
        &["principal", "handle", "action", "label"]
    }
    fn constant(
        &self,
        field: Component,
        literal: &Literal,
    ) -> Option<Component4<u32, u32, u8, u8>> {
        match field.0 {
            0 => number(literal).map(Component4::C0),
            1 => number(literal).map(Component4::C1),
            2 => action(literal)
                .filter(|a| [READ, RECEIVE, CONTACT, DECLASSIFY].contains(a))
                .map(Component4::C2),
            3 => match literal {
                Literal::String(name) if name == "untrusted" => Some(Component4::C3(0)),
                Literal::String(name) if name == "sink" => Some(Component4::C3(1)),
                _ => None,
            },
            _ => None,
        }
    }
}
