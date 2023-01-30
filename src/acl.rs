use crate::ctx::Ctx;

use posix_acl::{PosixACL, Qualifier};
use std::path::Path;

pub fn update_access_acl(ctx: &Ctx, path: &Path) {
    let vp = &ctx.verbose_printer;
    vp.print1(format!("{} -> Scanning Access ACLs", path.display()));
    let mut acl = match PosixACL::read_acl(path) {
        Ok(acl) => acl,
        Err(e) => {
            eprintln!("{} -> Error reading ACL: {e}", path.display());
            return;
        }
    };
    let mut changed = false;
    for entry in acl.entries() {
        match entry.qual {
            Qualifier::User(uid) => {
                let new_uid = ctx.uidmap.get(&uid);
                match new_uid {
                    Some(new_uid) => {
                        vp.print1(format!(
                            "{} -> Uid {uid} found in Access ACL, replacing with uid {new_uid}",
                            path.display()
                        ));
                        if ctx.noop {
                            vp.print1(format!("{} -> noop, not making changes", path.display()));
                            return;
                        }
                        vp.print1(format!(
                            "{} -> Adding Access ACL for new uid: {new_uid}",
                            path.display()
                        ));
                        vp.print1(format!(
                            "{} -> Removing Access ACL for old uid: {uid}",
                            path.display()
                        ));
                        acl.remove(Qualifier::User(uid));
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
                        vp.print1(format!(
                            "{} -> Gid {gid} found in Access ACL, replacing with gid {new_gid}",
                            path.display()
                        ));
                        if ctx.noop {
                            vp.print1(format!("{} -> noop, not making changes", path.display()));
                            return;
                        }
                        vp.print1(format!(
                            "{} -> Removing Access ACL for old gid: {gid}",
                            path.display()
                        ));
                        acl.remove(Qualifier::Group(gid));
                        vp.print1(format!(
                            "{} -> Adding Access ACL for new gid: {new_gid}",
                            path.display()
                        ));
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
        return;
    }
    vp.print1(format!("{} -> Writing changes to ACL", path.display()));
    match acl.write_acl(path) {
        Ok(_) => vp.print1(format!(
            "{} -> Successfully wrote changes to ACL",
            path.display()
        )),
        Err(e) => eprintln!("{} -> Failed to write acl: {e}", path.display()),
    }
}

pub fn update_default_acl(ctx: &Ctx, path: &Path) {
    let vp = &ctx.verbose_printer;
    vp.print1(format!("{} -> Scanning Default ACLs", path.display()));
    let mut acl = match PosixACL::read_default_acl(path) {
        Ok(acl) => acl,
        Err(e) => {
            eprintln!(
                "{} -> Error reading default ACL. This should only be run against directories: {e}",
                path.display()
            );
            return;
        }
    };
    let mut changed = false;
    for entry in acl.entries() {
        match entry.qual {
            Qualifier::User(uid) => {
                let new_uid = ctx.uidmap.get(&uid);
                match new_uid {
                    Some(new_uid) => {
                        vp.print1(format!(
                            "{} -> Uid {uid} found in Default ACL, replacing with uid {new_uid}",
                            path.display()
                        ));
                        if ctx.noop {
                            vp.print1(format!("{} -> noop, not making changes", path.display()));
                            continue;
                        }
                        vp.print1(format!(
                            "{} -> Removing Default ACL for old uid: {uid}",
                            path.display()
                        ));
                        acl.remove(Qualifier::User(uid));
                        vp.print1(format!(
                            "{} -> Adding Default ACL for new uid: {new_uid}",
                            path.display()
                        ));
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
                        vp.print1(format!(
                            "{} -> Gid {gid} found in Default ACL, replacing with gid {new_gid}",
                            path.display()
                        ));
                        if ctx.noop {
                            vp.print1(format!("{} -> noop, not making changes", path.display()));
                            continue;
                        }
                        vp.print1(format!(
                            "{} -> Removing Default ACL for old gid: {gid}",
                            path.display()
                        ));
                        acl.remove(Qualifier::Group(gid));
                        vp.print1(format!(
                            "{} -> Adding Default ACL for new gid: {new_gid}",
                            path.display()
                        ));
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
        return;
    }
    vp.print1(format!(
        "{} -> Writing changes to Default ACL",
        path.display()
    ));
    if !ctx.noop {
        match acl.write_default_acl(path) {
            Ok(_) => vp.print1(format!(
                "{} -> Successfully wrote changes to Default ACL",
                path.display()
            )),
            Err(e) => {
                eprintln!("{} -> Failed to write acl: {e}", path.display());
                return;
            }
        }
    } else {
        vp.print1(format!("{} -> noop, not making changes", path.display()));
    }
}
