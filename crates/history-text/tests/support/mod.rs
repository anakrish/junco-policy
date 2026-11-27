use history_syntax::{Component, Component3, Component4};
use history_text::{CoordinateSpec, Literal, LiteralKinds, Resolver, Vocabulary};

pub type Lock = (u32, u32, u32);
pub type Flow = (u32, u32, u32, u32);
pub const READ: u32 = 0;
pub const EDIT: u32 = 1;
pub const RELEASE: u32 = 2;
pub const REMOVE: u32 = 3;
pub const RECEIVE: u32 = 4;
pub const CONTACT: u32 = 5;
pub const DECLASSIFY: u32 = 6;

const IDS: LiteralKinds = LiteralKinds {
    string: false,
    integer: true,
    boolean: false,
};
const SYMBOLS: LiteralKinds = LiteralKinds {
    string: false,
    integer: false,
    boolean: false,
};
const LABELS: LiteralKinds = LiteralKinds {
    string: true,
    integer: true,
    boolean: false,
};
const LOCK: [CoordinateSpec<'static>; 3] = [
    CoordinateSpec {
        name: "principal",
        domain: "principal-id",
        literals: IDS,
    },
    CoordinateSpec {
        name: "action",
        domain: "lock-action",
        literals: SYMBOLS,
    },
    CoordinateSpec {
        name: "resource",
        domain: "resource-id",
        literals: IDS,
    },
];
const FLOW: [CoordinateSpec<'static>; 4] = [
    CoordinateSpec {
        name: "principal",
        domain: "principal-id",
        literals: IDS,
    },
    CoordinateSpec {
        name: "handle",
        domain: "handle-id",
        literals: IDS,
    },
    CoordinateSpec {
        name: "action",
        domain: "flow-action",
        literals: SYMBOLS,
    },
    CoordinateSpec {
        name: "label",
        domain: "label-id",
        literals: LABELS,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolveError;
impl core::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("unknown symbol, unsupported literal or out-of-range value")
    }
}
impl core::error::Error for ResolveError {}

fn number(literal: Literal<'_>) -> Result<u32, ResolveError> {
    if let Literal::Integer(value) = literal {
        value.parse().map_err(|_| ResolveError)
    } else {
        Err(ResolveError)
    }
}
fn action(literal: Literal<'_>, flow: bool) -> Result<u32, ResolveError> {
    match literal {
        Literal::Symbol("read") => Ok(READ),
        Literal::Symbol("edit") if !flow => Ok(EDIT),
        Literal::Symbol("release") if !flow => Ok(RELEASE),
        Literal::Symbol("remove") if !flow => Ok(REMOVE),
        Literal::Symbol("receive") if flow => Ok(RECEIVE),
        Literal::Symbol("contact") if flow => Ok(CONTACT),
        Literal::Symbol("declassify") if flow => Ok(DECLASSIFY),
        _ => Err(ResolveError),
    }
}
pub struct LockVocabulary;
impl Resolver<Lock> for LockVocabulary {
    type Error = ResolveError;
    fn vocabulary(&self) -> Vocabulary<'_> {
        Vocabulary {
            id: "lock/1",
            coordinates: &LOCK,
        }
    }
    fn resolve(
        &self,
        coordinate: Component,
        literal: Literal<'_>,
    ) -> Result<Component3<u32, u32, u32>, ResolveError> {
        match coordinate.index() {
            0 => number(literal).map(Component3::C0),
            1 => action(literal, false).map(Component3::C1),
            2 => number(literal).map(Component3::C2),
            _ => Err(ResolveError),
        }
    }
}
pub struct FlowVocabulary;
impl Resolver<Flow> for FlowVocabulary {
    type Error = ResolveError;
    fn vocabulary(&self) -> Vocabulary<'_> {
        Vocabulary {
            id: "flow/1",
            coordinates: &FLOW,
        }
    }
    fn resolve(
        &self,
        coordinate: Component,
        literal: Literal<'_>,
    ) -> Result<Component4<u32, u32, u32, u32>, ResolveError> {
        match coordinate.index() {
            0 => number(literal).map(Component4::C0),
            1 => number(literal).map(Component4::C1),
            2 => action(literal, true).map(Component4::C2),
            3 => match literal {
                Literal::String("untrusted") => Ok(Component4::C3(10)),
                Literal::String("sink") => Ok(Component4::C3(20)),
                _ => number(literal).map(Component4::C3),
            },
            _ => Err(ResolveError),
        }
    }
}
