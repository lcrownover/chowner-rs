use crate::ctx::Ctx;
use crate::types::{AclType, PermissionType};

use posix_acl::{ACLEntry, PosixACL, Qualifier};
use std::path::Path;

/// Returns the User or Group `PosixACL` at the given path
///
/// # Arguments
///
/// * `atype` - Type of ACL you expect, either User or Group
///
/// * `path` - Path to the filesystem object
///
fn get_acl(atype: AclType, path: &Path) -> Option<PosixACL> {
    if path.is_symlink() {
        return None;
    }
    let acl = match atype {
        AclType::Access => PosixACL::read_acl(path),
        AclType::Default => PosixACL::read_default_acl(path),
    };
    match acl {
        Ok(acl) => return Some(acl),
        Err(e) => {
            eprintln!("{} -> Error reading ACL: {e}", path.display());
            return None;
        }
    };
}

// TODO(lcrown): This is a mess, why do we need entry? ugh. fix it.
//
/// Do the work to set the ACL according to all the provided data.
/// Returns true if any changes were made, otherwise false.
///
/// # Arguments
///
/// * `ctx` - Context object used throughout the application
///
/// * `path` - Path to the filesystem object
///
/// * `acl` - Mutable reference to the `PosixACL` that we want to change
///
/// * `current_id` - ID of the current object, either UID or GID
///
/// * `entry` - The ACL entry itself, for getting the permission for resetting it
///
/// * `ptype` - The permission type that you want changed, User or Group
///
fn set_acl_permission(
    ctx: &Ctx,
    path: &Path,
    acl: &mut PosixACL,
    acl_type: AclType,
    current_id: u32,
    entry: ACLEntry,
    ptype: PermissionType,
) -> bool {
    let vp = &ctx.verbose_printer;
    let atype_str = match acl_type {
        AclType::Access => "access",
        AclType::Default => "default",
    };
    let new_id = match ptype {
        PermissionType::User => ctx.uidmap.get(&current_id),
        PermissionType::Group => ctx.gidmap.get(&current_id),
    };
    match new_id {
        Some(new_id) => {
            vp.print1(format!(
                "{} -> {} id {} found in {} ACL, replacing with uid {}",
                path.display(),
                ptype,
                current_id,
                atype_str,
                new_id,
            ));
            if ctx.noop {
                vp.print1(format!("{} -> NOOP: Not making changes", path.display()));
                return false;
            }
            vp.print1(format!(
                "{} -> Adding {} ACL for new {} id: {}",
                path.display(),
                atype_str,
                ptype,
                new_id,
            ));
            match ptype {
                PermissionType::User => acl.set(Qualifier::User(*new_id), entry.perm),
                PermissionType::Group => acl.set(Qualifier::Group(*new_id), entry.perm),
            }
            vp.print1(format!(
                "{} -> Removing {} ACL for old {} id: {}",
                path.display(),
                atype_str,
                ptype,
                current_id,
            ));
            match ptype {
                PermissionType::User => acl.remove(Qualifier::User(current_id)),
                PermissionType::Group => acl.remove(Qualifier::Group(current_id)),
            };
            return true;
        }
        None => return false,
    }
}

/// Write the ACL data, essentially "saving" it
///
/// # Arguments
///
/// * `ctx` - Context object used throughout the application
///
/// * `path` - Path to the filesystem object
///
/// * `acl` - Mutable reference to the `PosixACL` you want to save
///
fn write_acl(ctx: &Ctx, path: &Path, acl: &mut PosixACL, acl_type: AclType) {
    let vp = &ctx.verbose_printer;
    vp.print1(format!("{} -> Writing changes to ACL", path.display()));
    let res = match acl_type {
        AclType::Access => acl.write_acl(path),
        AclType::Default => acl.write_default_acl(path),
    };
    match res {
        Ok(_) => vp.print1(format!(
            "{} -> Successfully wrote changes to ACL",
            path.display()
        )),
        Err(e) => eprintln!("{} -> Failed to write acl: {e}", path.display()),
    }
}

/// Using the data in our context, update the ACLs on the given `path`
///
/// # Arguments
///
/// * `ctx` - Context object used throughout the application
///
/// * `path` - Path to the filesystem object
///
pub fn update_acl(ctx: &Ctx, path: &Path) {
    let vp = &ctx.verbose_printer;
    vp.print1(format!("{} -> Scanning ACLs", path.display()));

    // get the acl, if it's none, it already printed an error, lets just skip the file
    let mut access_acl = match get_acl(AclType::Access, path) {
        Some(acl) => acl,
        None => return,
    };

    // flag that only writes access acl if any changes were made
    let mut access_changed = false;

    // go through each entry and:
    //  - if the current uid matches one of the current uids in our map
    //      - add the new uid with the same permission
    //      - remove the old uid
    //  - if the current gid matches one of the current gids in our map
    //      - add the new gid with the same permission
    //      - remove the old gid
    for entry in access_acl.entries() {
        match entry.qual {
            Qualifier::User(current_uid) => {
                if set_acl_permission(
                    &ctx,
                    path,
                    &mut access_acl,
                    AclType::Access,
                    current_uid,
                    entry,
                    PermissionType::User,
                ) {
                    access_changed = true
                }
            }
            Qualifier::Group(current_gid) => {
                if set_acl_permission(
                    &ctx,
                    path,
                    &mut access_acl,
                    AclType::Access,
                    current_gid,
                    entry,
                    PermissionType::Group,
                ) {
                    access_changed = true
                }
            }
            _ => (),
        }
    }

    // write changes to the access acl
    if access_changed {
        write_acl(&ctx, path, &mut access_acl, AclType::Access);
    }

    // if it's not a directory, we don't need to update the default acl
    if !path.is_dir() {
        return;
    }

    // flag that only writes access acl if any changes were made
    let mut default_changed = false;

    let mut default_acl = match get_acl(AclType::Default, path) {
        Some(acl) => acl,
        None => return,
    };
    // run the write against AclType::Default
    for entry in default_acl.entries() {
        match entry.qual {
            Qualifier::User(current_uid) => {
                if set_acl_permission(
                    &ctx,
                    path,
                    &mut default_acl,
                    AclType::Default,
                    current_uid,
                    entry,
                    PermissionType::User,
                ) {
                    default_changed = true
                }
            }
            Qualifier::Group(current_gid) => {
                if set_acl_permission(
                    &ctx,
                    path,
                    &mut default_acl,
                    AclType::Default,
                    current_gid,
                    entry,
                    PermissionType::Group,
                ) {
                    default_changed = true
                }
            }
            _ => (),
        }
    }

    // otherwise we should write the changes
    if default_changed {
        write_acl(&ctx, path, &mut default_acl, AclType::Default);
    }
}
