use crate::acl;
use crate::ctx::Ctx;
use anyhow::{bail, Result};
use file_owner::PathExt;
use rayon::prelude::*;
use std::fs;
use std::fs::Metadata;
use std::fs::{DirEntry, ReadDir};
// use std::os::linux::fs::MetadataExt;
use std::os::macos::fs::MetadataExt;
use std::path::Path;

pub fn parse_file_listing(files: ReadDir) -> Vec<DirEntry> {
    let mut outfiles: Vec<DirEntry> = vec![];
    for file in files {
        match file {
            Ok(de) => outfiles.push(de),
            Err(e) => {
                eprintln!("failed to parse file: {e}");
                continue;
            }
        };
    }
    outfiles
}

fn get_file_metadata(p: &Path) -> Result<Metadata, anyhow::Error> {
    let fm = match p.metadata() {
        Ok(fm) => fm,
        Err(e) => {
            bail!("{} -> failed to parse file metadata: {e}", p.display());
        }
    };
    Ok(fm)
}

fn get_file_listing(path: &Path) -> Result<ReadDir, anyhow::Error> {
    let file_listing = match fs::read_dir(path) {
        Ok(f) => f,
        Err(e) => {
            bail!("{} -> failed to stat file, error: {}", path.display(), e);
        }
    };
    Ok(file_listing)
}

fn change_uid(ctx: &Ctx, p: &Path) -> Result<(), anyhow::Error> {
    println!("{} -> Scanning uids", p.display());
    let fm = get_file_metadata(p.as_ref())?;
    let current_uid = fm.st_uid();
    match ctx.uidmap.get(&current_uid) {
        Some(new_uid) => {
            println!(
                "{} -> Found: Changing uid from {current_uid} to {new_uid}",
                p.display()
            );
            if !ctx.noop {
                match p.set_owner(*new_uid) {
                    Ok(_) => (),
                    Err(e) => {
                        eprintln!("{} -> Failed to set uid, error: {}", p.display(), e)
                    }
                };
            } else {
                println!("{} -> noop, not making changes", p.display());
            }
        }
        None => (),
    };
    Ok(())
}

fn change_gid(ctx: &Ctx, p: &Path) -> Result<(), anyhow::Error> {
    println!("{} -> Scanning gids", p.display());
    let fm = get_file_metadata(p.as_ref())?;
    let current_gid = fm.st_gid();
    match ctx.gidmap.get(&current_gid) {
        Some(new_gid) => {
            println!(
                "{} -> Found: Changing gid from {current_gid} to {new_gid}",
                p.display()
            );
            if !ctx.noop {
                match p.set_group(*new_gid) {
                    Ok(_) => (),
                    Err(e) => {
                        eprintln!("{} -> Failed to set gid, error: {}", p.display(), e)
                    }
                };
            }
        }
        None => (),
    };
    Ok(())
}

fn process_path(ctx: &Ctx, p: &Path, recurse: bool) -> Result<(), anyhow::Error> {
    // Skip symlinks, they're nuthin but trouble
    if p.is_symlink() {
        println!("{} -> Skipping symlink", p.display());
        return Ok(());
    }

    // Run the logic to check and swap old uid with new uid
    if !ctx.uidmap.is_empty() {
        change_uid(&ctx, &p)?;
    }
    if !ctx.gidmap.is_empty() {
        change_gid(&ctx, &p)?;
    }

    // Modify the posix ACLs if flag was provided
    // TODO(lcrown): see about refactoring these and skipping if the maps are empty
    if ctx.modify_acls {
        acl::update_access_acl(&ctx, &p)?;
        if p.is_dir() {
            acl::update_default_acl(&ctx, &p)?;
        }
    }

    // If the item is a dir, do it all again!
    if p.is_dir() && recurse {
        run_dir(&ctx, &p)?;
    }

    Ok(())
}

fn run_dir(ctx: &Ctx, path: &Path) -> Result<(), anyhow::Error> {
    // do the stuff to the provided Path with no recurse
    process_path(&ctx, path, false)?;

    // then list all its children and do the stuff
    let file_listing = get_file_listing(&path)?;
    let files = parse_file_listing(file_listing);

    files.par_iter().for_each(move |f| {
        match process_path(&ctx, &f.path(), true) {
            Ok(_) => (),
            Err(e) => eprintln!("{e}"),
        };
    });

    Ok(())
}

pub fn start(ctx: &Ctx, path: &impl AsRef<Path>) -> Result<(), anyhow::Error> {
    run_dir(&ctx, path.as_ref())?;
    Ok(())
}
