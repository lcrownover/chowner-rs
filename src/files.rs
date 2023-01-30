use crate::acl;
use crate::ctx::Ctx;
use anyhow::{bail, Result};
use core::fmt;
use file_owner::PathExt;
use rayon::prelude::*;
use std::fs;
use std::fs::Metadata;
use std::fs::ReadDir;
// use std::os::linux::fs::MetadataExt;
use std::os::macos::fs::MetadataExt;
use std::path::{Path, PathBuf};

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

pub struct PermissionOperation {
    ptype: PermissionType,
    current_id: u32,
    new_id: u32,
    path: PathBuf,
}

fn get_file_listing(path: &Path) -> Result<ReadDir, anyhow::Error> {
    let file_listing = match fs::read_dir(path) {
        Ok(f) => f,
        Err(e) => {
            bail!("{} -> Failed to stat file, error: {}", path.display(), e);
        }
    };
    Ok(file_listing)
}

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

fn get_file_paths(path: &Path) -> Result<Vec<PathBuf>, anyhow::Error> {
    let fl = get_file_listing(path)?;
    let files = parse_file_listing(fl);
    Ok(files)
}

fn get_file_metadata(p: &Path) -> Result<Metadata, anyhow::Error> {
    let fm = match p.metadata() {
        Ok(fm) => fm,
        Err(e) => {
            bail!("{} -> Failed to parse file metadata: {e}", p.display());
        }
    };
    Ok(fm)
}

fn update_file_permissions(ctx: &Ctx, po: &PermissionOperation) {
    let vp = &ctx.verbose_printer;
    vp.print1(format!(
        "{} -> Found: Changing {} id from {} to {}",
        po.path.display(),
        po.ptype.to_string(),
        po.current_id,
        po.new_id,
    ));
    if !ctx.noop {
        match po.path.set_owner(po.new_id) {
            Ok(_) => (),
            Err(e) => {
                eprintln!("{} -> Failed to set uid, error: {}", po.path.display(), e)
            }
        };
    } else {
        vp.print1(format!("{} -> NOOP, not making changes", po.path.display()));
    }
}

fn process_user_permission_operation(
    ctx: &Ctx,
    m: &Metadata,
    path: &Path,
) -> Option<PermissionOperation> {
    let current_uid = m.st_uid();
    let new_uid = match ctx.uidmap.get(&current_uid) {
        Some(new_uid) => new_uid,
        None => return None,
    };
    return Some(PermissionOperation {
        ptype: PermissionType::User,
        current_id: current_uid,
        new_id: *new_uid,
        path: path.to_path_buf(),
    });
}

fn process_group_permission_operation(
    ctx: &Ctx,
    m: &Metadata,
    path: &Path,
) -> Option<PermissionOperation> {
    let current_gid = m.st_gid();
    let new_gid = match ctx.gidmap.get(&current_gid) {
        Some(new_gid) => new_gid,
        None => return None,
    };
    return Some(PermissionOperation {
        ptype: PermissionType::Group,
        current_id: current_gid,
        new_id: *new_gid,
        path: path.to_path_buf(),
    });
}

fn process_file_permissions(ctx: &Ctx, path: &Path) {
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
    // do uid stuff
    if !ctx.uidmap.is_empty() {
        match process_user_permission_operation(&ctx, &fm, path) {
            Some(po) => ops.push(po),
            None => (),
        }
    }
    if !ctx.gidmap.is_empty() {
        match process_group_permission_operation(&ctx, &fm, path) {
            Some(po) => ops.push(po),
            None => (),
        }
    }

    for po in ops {
        update_file_permissions(&ctx, &po);
    }
}

fn process_path(ctx: &Ctx, path: &Path, recurse: bool) -> Result<(), anyhow::Error> {
    let vp = &ctx.verbose_printer;
    // Skip symlinks, they're nuthin but trouble
    if path.is_symlink() {
        vp.print1(format!("{} -> Skipping symlink", path.display()));
        return Ok(());
    }

    process_file_permissions(&ctx, path);

    // Modify the posix ACLs if flag was provided
    // TODO(lcrown): see about refactoring these and skipping if the maps are empty
    if ctx.modify_acls {
        acl::update_access_acl(&ctx, &path);
        if path.is_dir() {
            acl::update_default_acl(&ctx, &path);
        }
    }

    // If the item is a dir, do it all again!
    if path.is_dir() && recurse {
        run_dir(&ctx, &path);
    }

    Ok(())
}

fn run_dir(ctx: &Ctx, path: &Path) {
    // handle errors in here because we want to gracefully continue
    // everything downstream should bail!() and bubble up here
    // if anything fails, we just error print, return a unit, and keep going

    // do the stuff to the provided Path with no recurse
    match process_path(&ctx, path, false) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    // then list all its children and do the stuff
    let files = match get_file_paths(path) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    files.par_iter().for_each(move |f| {
        match process_path(&ctx, &f.as_path(), true) {
            Ok(_) => (),
            Err(e) => eprintln!("{e}"),
        };
    });
}

pub fn start(ctx: &Ctx, path: &impl AsRef<Path>) {
    run_dir(&ctx, path.as_ref());
}
