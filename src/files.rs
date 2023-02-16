use crate::acl;
use crate::ctx::Ctx;
use crate::types::PermissionType;
use anyhow::{bail, Result};
use file_owner::PathExt;
use std::fs;
use std::fs::Metadata;
use std::fs::ReadDir;
use std::os::linux::fs::MetadataExt;
// use std::os::macos::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// This represents a single File Permission change operation
pub struct PermissionOperation {
    /// Either a User permission, or Group permission
    ptype: PermissionType,
    /// The current id of the permission
    current_id: u32,
    /// The new id for the permission
    new_id: u32,
    /// Path to the object
    path: PathBuf,
}

/// Gets a listing of file objects
///
/// # Arguments
///
/// * `path` - Path to the directory
///
fn get_directory_listing(path: &Path) -> Result<ReadDir, anyhow::Error> {
    let dir_listing = match fs::read_dir(path) {
        Ok(f) => f,
        Err(e) => {
            bail!(
                "{} -> Failed to get directory listing, error: {}",
                path.display(),
                e
            );
        }
    };
    Ok(dir_listing)
}

/// Returns a list of paths from the given directory listing
///
/// # Arguments
///
/// * `file_listing` - `ReadDir` object returned from calling `fs::read_dir()`
///
pub fn parse_file_listing(file_listing: ReadDir) -> Vec<PathBuf> {
    let mut outfiles: Vec<PathBuf> = vec![];
    for file in file_listing {
        match file {
            Ok(de) => outfiles.push(de.path()),
            Err(e) => {
                eprintln!("Error reading file entry: {e}");
                continue;
            }
        };
    }
    outfiles
}

/// Returns a list of child paths for a given parent path
///
/// # Arguments
///
/// * `path` - Path to the parent directory
///
pub fn get_children_paths(path: &Path) -> Result<Vec<PathBuf>, anyhow::Error> {
    let fl = get_directory_listing(path)?;
    let files = parse_file_listing(fl);
    Ok(files)
}

/// Returns the metadata for a file
///
/// # Arguments
///
/// * `path` - Path to the object
///
fn get_file_metadata(path: &Path) -> Result<Metadata, anyhow::Error> {
    let fm = match path.metadata() {
        Ok(fm) => fm,
        Err(e) => {
            bail!("{} -> Failed to parse file metadata: {e}", path.display());
        }
    };
    Ok(fm)
}

/// Uses a `PermissionOperation` to apply settings to a filesystem object.
///
/// # Arguments
///
/// * `ctx` - Context object used throughout the application
///
/// * `perm_op` - `PermissionOperation` object used to signify a permission change
///
fn set_file_permission(ctx: &Ctx, perm_op: &PermissionOperation) {
    let vp = &ctx.verbose_printer;
    vp.print1(format!(
        "{} -> Found: Changing {} id from {} to {}",
        perm_op.path.display(),
        perm_op.ptype.to_string(),
        perm_op.current_id,
        perm_op.new_id,
    ));
    if ctx.noop {
        vp.print1(format!(
            "{} -> NOOP: Not making changes",
            perm_op.path.display()
        ));
        return;
    }
    match &perm_op.ptype {
        PermissionType::User => {
            match perm_op.path.set_owner(perm_op.new_id) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!(
                        "{} -> Failed to set uid, error: {}",
                        perm_op.path.display(),
                        e
                    )
                }
            };
        }
        PermissionType::Group => {
            match perm_op.path.set_group(perm_op.new_id) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!(
                        "{} -> Failed to set gid, error: {}",
                        perm_op.path.display(),
                        e
                    )
                }
            };
        }
    }
}

/// Inspects the provided file metadata and optionally returns
/// a `PermissionOperation` if a change is needed.
///
/// # Arguments
///
/// * `ctx` - Context object used throughout the application
///
/// * `metadata` - File metadata
///
/// * `path` - Path to the object
///
fn get_permission_operation(
    ctx: &Ctx,
    metadata: &Metadata,
    path: &Path,
    ptype: PermissionType,
) -> Option<PermissionOperation> {
    let current_id = match ptype {
        PermissionType::User => metadata.st_uid(),
        PermissionType::Group => metadata.st_gid(),
    };
    let new_id = match ptype {
        PermissionType::User => match ctx.uidmap.get(&current_id) {
            Some(new_id) => *new_id,
            None => return None,
        },
        PermissionType::Group => match ctx.gidmap.get(&current_id) {
            Some(new_id) => *new_id,
            None => return None,
        },
    };
    return Some(PermissionOperation {
        ptype: PermissionType::User,
        current_id,
        new_id,
        path: path.to_path_buf(),
    });
}

/// Checks the object at `path` against the user and group maps.
/// If it finds that the object has a matching uid or gid to the keys in
/// the respective maps, it will replace those uid/gids with the values in the map.
///
/// # Arguments
///
/// * `ctx` - Context object used throughout the application
///
/// * `path` - Path to the object
///
fn update_file_permissions(ctx: &Ctx, path: &Path) {
    let vp = &ctx.verbose_printer;
    vp.print1(format!("{} -> Processing file permissions", path.display()));
    let fm = match get_file_metadata(path.as_ref()) {
        Ok(fm) => fm,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    let mut ops: Vec<PermissionOperation> = vec![];
    if !ctx.uidmap.is_empty() {
        match get_permission_operation(&ctx, &fm, path, PermissionType::User) {
            Some(po) => ops.push(po),
            None => (),
        }
    }
    if !ctx.gidmap.is_empty() {
        match get_permission_operation(&ctx, &fm, path, PermissionType::Group) {
            Some(po) => ops.push(po),
            None => (),
        }
    }

    for po in ops {
        set_file_permission(&ctx, &po);
    }
}

/// The primary function for processing paths.
/// Both files and directories need their permissions and ACLs modified,
/// but we should skip symlinks.
///
/// First, the file permissions are updated. Then if the user passed the ACL flag,
/// update the ACLs.
///
pub fn process_path(ctx: &Ctx, path: &Path) {
    // Update unix permissions
    if !ctx.skip_permissions {
        update_file_permissions(&ctx, path);
    }

    // Modify the posix ACLs if flag was provided
    if !ctx.skip_acls {
        acl::update_acl(&ctx, &path);
    }
}
