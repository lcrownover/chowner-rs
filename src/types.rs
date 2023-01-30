use core::fmt;

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

pub enum AclType {
    Access,
    Default,
}
