use std::collections::HashMap;

use crate::util::VerbosePrinter;

/// Context structure for storing cross-application data
#[derive(Debug)]
pub struct Ctx {
    /// If noop, nothing will be written, only processed
    pub noop: bool,
    /// If skip_permissions, Posix permissions will not be modified
    pub skip_permissions: bool,
    /// If skip_acls, Posix ACLs will be not be modified
    pub skip_acls: bool,
    /// Map of old:new uids. Example 57:219883
    pub uidmap: HashMap<u32, u32>,
    /// Map of old:new gids. Example 57:219883
    pub gidmap: HashMap<u32, u32>,
    /// List of ignored paths
    pub ignore_paths: Vec<String>,
    /// Reference to a verbose printer
    pub verbose_printer: VerbosePrinter,
}
