use std::collections::HashMap;

use crate::util::VerbosePrinter;

#[derive(Debug)]
pub struct Ctx {
    pub noop: bool,
    pub modify_acls: bool,
    pub uidmap: HashMap<u32, u32>,
    pub gidmap: HashMap<u32, u32>,
    pub verbose_printer: VerbosePrinter,
}
