use crate::ctx::Ctx;

use anyhow::{bail, Result};
use posix_acl::{PosixACL, Qualifier};
use std::path::Path;

pub fn update_access_acl(ctx: &Ctx, path: &Path) -> Result<(), anyhow::Error> {
    println!("{} -> Scanning Access ACLs", path.display());
    let mut acl = match PosixACL::read_acl(path) {
        Ok(acl) => acl,
        Err(e) => bail!("{} -> Error reading ACL: {e}", path.display()),
    };
    let mut changed = false;
    for entry in acl.entries() {
        // println!("Processing entry: {entry:?}");
        match entry.qual {
            Qualifier::User(uid) => {
                let new_uid = ctx.uidmap.get(&uid);
                match new_uid {
                    Some(new_uid) => {
                        println!(
                            "{} -> Uid {uid} found in Access ACL, replacing with uid {new_uid}",
                            path.display()
                        );
                        if ctx.noop {
                            println!("{} -> noop, not making changes", path.display());
                            continue;
                        }
                        println!(
                            "{} -> Removing Access ACL for old uid: {uid}",
                            path.display()
                        );
                        acl.remove(Qualifier::User(uid));
                        println!(
                            "{} -> Adding Access ACL for new uid: {new_uid}",
                            path.display()
                        );
                        acl.set(Qualifier::User(*new_uid), entry.perm);
                        changed = true;
                    }
                    None => (),
                }
            }
            Qualifier::Group(gid) => {
                let new_gid = ctx.gidmap.get(&gid);
                match new_gid {
                    Some(new_gid) => {
                        println!(
                            "{} -> Gid {gid} found in Access ACL, replacing with gid {new_gid}",
                            path.display()
                        );
                        if ctx.noop {
                            println!("{} -> noop, not making changes", path.display());
                            continue;
                        }
                        println!(
                            "{} -> Removing Access ACL for old gid: {gid}",
                            path.display()
                        );
                        acl.remove(Qualifier::Group(gid));
                        println!(
                            "{} -> Adding Access ACL for new gid: {new_gid}",
                            path.display()
                        );
                        acl.set(Qualifier::Group(*new_gid), entry.perm);
                        changed = true;
                    }
                    None => (),
                }
            }
            _ => (),
        }
    }
    if !changed {
        return Ok(());
    }
    println!("{} -> Writing changes to ACL", path.display());
    match acl.write_acl(path) {
        Ok(_) => println!("{} -> Successfully wrote changes to ACL", path.display()),
        Err(e) => bail!("{} -> Failed to write acl: {e}", path.display()),
    }
    Ok(())
}

pub fn update_default_acl(ctx: &Ctx, path: &Path) -> Result<(), anyhow::Error> {
    println!("{} -> Scanning Default ACLs", path.display());
    let mut acl = match PosixACL::read_default_acl(path) {
        Ok(acl) => acl,
        Err(e) => {
            bail!(
                "{} -> Error reading default ACL. This should only be run against directories: {e}",
                path.display()
            )
        }
    };
    let mut changed = false;
    for entry in acl.entries() {
        match entry.qual {
            Qualifier::User(uid) => {
                let new_uid = ctx.uidmap.get(&uid);
                match new_uid {
                    Some(new_uid) => {
                        println!(
                            "{} -> Uid {uid} found in Default ACL, replacing with uid {new_uid}",
                            path.display()
                        );
                        if ctx.noop {
                            println!("{} -> noop, not making changes", path.display());
                            continue;
                        }
                        println!(
                            "{} -> Removing Default ACL for old uid: {uid}",
                            path.display()
                        );
                        acl.remove(Qualifier::User(uid));
                        println!(
                            "{} -> Adding Default ACL for new uid: {new_uid}",
                            path.display()
                        );
                        acl.set(Qualifier::User(*new_uid), entry.perm);
                        changed = true;
                    }
                    None => (),
                }
            }
            Qualifier::Group(gid) => {
                let new_gid = ctx.gidmap.get(&gid);
                match new_gid {
                    Some(new_gid) => {
                        println!(
                            "{} -> Gid {gid} found in Default ACL, replacing with gid {new_gid}",
                            path.display()
                        );
                        if ctx.noop {
                            println!("{} -> noop, not making changes", path.display());
                            continue;
                        }
                        println!(
                            "{} -> Removing Default ACL for old gid: {gid}",
                            path.display()
                        );
                        acl.remove(Qualifier::Group(gid));
                        println!(
                            "{} -> Adding Default ACL for new gid: {new_gid}",
                            path.display()
                        );
                        acl.set(Qualifier::Group(*new_gid), entry.perm);
                        changed = true;
                    }
                    None => (),
                }
            }
            _ => (),
        }
    }
    if !changed {
        return Ok(());
    }
    println!("{} -> Writing changes to Default ACL", path.display());
    if !ctx.noop {
        match acl.write_default_acl(path) {
            Ok(_) => println!(
                "{} -> Successfully wrote changes to Default ACL",
                path.display()
            ),
            Err(e) => bail!("{} -> Failed to write acl: {e}", path.display()),
        }
    } else {
        println!("{} -> noop, not making changes", path.display());
    }
    Ok(())
}
