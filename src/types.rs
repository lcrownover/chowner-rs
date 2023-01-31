use core::fmt;

/// What type of permission we're expecting
pub enum PermissionType {
    User,
    Group,
}

impl fmt::Display for PermissionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PermissionType::User => write!(f, "User"),
            PermissionType::Group => write!(f, "Group"),
        }
    }
}

/// Two types of Posix ACLs
pub enum AclType {
    /// Access ACL is the normal acl type on files and directories
    Access,
    /// Default ACLs are only present on directories, and govern ACL inheritance
    Default,
}
