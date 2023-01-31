use std::collections::HashMap;

use crate::util::VerbosePrinter;

/// Context structure for storing cross-application data
#[derive(Debug)]
pub struct Ctx {
    /// If noop, nothing will be written, only processed
    pub noop: bool,
    /// If modify_acls, Posix ACLs will be modified alongside Unix permissions
    pub modify_acls: bool,
    /// Map of old:new uids. Example 57:219883
    pub uidmap: HashMap<u32, u32>,
    /// Map of old:new gids. Example 57:219883
    pub gidmap: HashMap<u32, u32>,
    /// Reference to a verbose printer
    pub verbose_printer: VerbosePrinter,
}
