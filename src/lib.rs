use std::collections::HashMap;
#[derive(Debug)]
pub struct Ctx {
    pub noop: bool,
    pub modify_acls: bool,
    pub uidmap: HashMap<u32, u32>,
    pub gidmap: HashMap<u32, u32>,
}

pub mod acl {
    use crate::Ctx;
    use anyhow::{bail, Result};
    use posix_acl::{PosixACL, Qualifier};
    use std::path::Path;

    pub fn update_access_acl(ctx: &Ctx, path: &impl AsRef<Path>) -> Result<(), anyhow::Error> {
        println!("{} -> Scanning Access ACLs", path.as_ref().display());
        let mut acl = match PosixACL::read_acl(path) {
            Ok(acl) => acl,
            Err(e) => bail!("{} -> Error reading ACL: {e}", path.as_ref().display()),
        };
        for entry in acl.entries() {
            // println!("Processing entry: {entry:?}");
            match entry.qual {
                Qualifier::User(uid) => {
                    let new_uid = ctx.uidmap.get(&uid);
                    match new_uid {
                        Some(new_uid) => {
                            println!(
                                "{} -> Uid {uid} found in ACL, replacing with uid {new_uid}",
                                path.as_ref().display()
                            );
                            if ctx.noop {
                                println!("{} -> noop, not making changes", path.as_ref().display());
                                continue;
                            }
                            println!(
                                "{} -> Removing Access ACL for old uid: {uid}",
                                path.as_ref().display()
                            );
                            acl.remove(Qualifier::User(uid));
                            println!(
                                "{} -> Adding Access ACL for new uid: {new_uid}",
                                path.as_ref().display()
                            );
                            acl.set(Qualifier::User(*new_uid), entry.perm)
                        }
                        None => (),
                    }
                }
                Qualifier::Group(gid) => {
                    let new_gid = ctx.gidmap.get(&gid);
                    match new_gid {
                        Some(new_gid) => {
                            println!(
                                "{} -> Gid {gid} found in ACL, replacing with gid {new_gid}",
                                path.as_ref().display()
                            );
                            if ctx.noop {
                                println!("{} -> noop, not making changes", path.as_ref().display());
                                continue;
                            }
                            println!(
                                "{} -> Removing Access ACL for old gid: {gid}",
                                path.as_ref().display()
                            );
                            acl.remove(Qualifier::Group(gid));
                            println!(
                                "{} -> Adding Access ACL for new gid: {new_gid}",
                                path.as_ref().display()
                            );
                            acl.set(Qualifier::Group(*new_gid), entry.perm)
                        }
                        None => (),
                    }
                }
                _ => (),
            }
        }
        println!("{} -> Writing changes to ACL", path.as_ref().display());
        match acl.write_acl(path) {
            Ok(_) => println!(
                "{} -> Successfully wrote changes to ACL",
                path.as_ref().display()
            ),
            Err(e) => bail!("{} -> Failed to write acl: {e}", path.as_ref().display()),
        }
        Ok(())
    }

    pub fn update_default_acl(ctx: &Ctx, path: &impl AsRef<Path>) -> Result<(), anyhow::Error> {
        println!("{} -> Scanning Default ACLs", path.as_ref().display());
        let mut acl = match PosixACL::read_default_acl(path) {
            Ok(acl) => acl,
            Err(e) => {
                bail!("{} -> Error reading default ACL. This should only be run against directories: {e}", path.as_ref().display())
            }
        };
        for entry in acl.entries() {
            // println!("Processing entry: {entry:?}");
            match entry.qual {
                Qualifier::User(uid) => {
                    let new_uid = ctx.uidmap.get(&uid);
                    match new_uid {
                        Some(new_uid) => {
                            println!(
                                "{} -> Uid {uid} found in ACL, replacing with uid {new_uid}",
                                path.as_ref().display()
                            );
                            if ctx.noop {
                                println!("{} -> noop, not making changes", path.as_ref().display());
                                continue;
                            }
                            println!(
                                "{} -> Removing Default ACL for old uid: {uid}",
                                path.as_ref().display()
                            );
                            acl.remove(Qualifier::User(uid));
                            println!(
                                "{} -> Adding Default ACL for new uid: {new_uid}",
                                path.as_ref().display()
                            );
                            acl.set(Qualifier::User(*new_uid), entry.perm)
                        }
                        None => (),
                    }
                }
                Qualifier::Group(gid) => {
                    let new_gid = ctx.gidmap.get(&gid);
                    match new_gid {
                        Some(new_gid) => {
                            println!(
                                "{} -> Gid {gid} found in ACL, replacing with gid {new_gid}",
                                path.as_ref().display()
                            );
                            if ctx.noop {
                                println!("{} -> noop, not making changes", path.as_ref().display());
                                continue;
                            }
                            println!(
                                "{} -> Removing Default ACL for old gid: {gid}",
                                path.as_ref().display()
                            );
                            acl.remove(Qualifier::Group(gid));
                            println!(
                                "{} -> Adding Default ACL for new gid: {new_gid}",
                                path.as_ref().display()
                            );
                            acl.set(Qualifier::Group(*new_gid), entry.perm)
                        }
                        None => (),
                    }
                }
                _ => (),
            }
        }
        println!(
            "{} -> Writing changes to Default ACL",
            path.as_ref().display()
        );
        if !ctx.noop {
            match acl.write_acl(path) {
                Ok(_) => println!(
                    "{} -> Successfully wrote changes to Default ACL",
                    path.as_ref().display()
                ),
                Err(e) => bail!("{} -> Failed to write acl: {e}", path.as_ref().display()),
            }
        } else {
            println!("{} -> noop, not making changes", path.as_ref().display());
        }
        Ok(())
    }
}

pub mod files {
    use crate::acl;
    use crate::Ctx;
    use anyhow::{bail, Result};
    use file_owner::PathExt;
    use rayon::prelude::*;
    use std::fs;
    use std::fs::Metadata;
    use std::fs::{DirEntry, ReadDir};
    use std::os::linux::fs::MetadataExt;
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

    fn get_file_listing(path: &impl AsRef<Path>) -> Result<ReadDir, anyhow::Error> {
        let file_listing = match fs::read_dir(path) {
            Ok(f) => f,
            Err(e) => {
                bail!(
                    "{} -> failed to stat file, error: {}",
                    path.as_ref().display(),
                    e
                );
            }
        };
        Ok(file_listing)
    }

    fn change_uid(ctx: &Ctx, p: &impl AsRef<Path>) -> Result<(), anyhow::Error> {
        println!("{} -> Scanning uids", p.as_ref().display());
        let fm = get_file_metadata(p.as_ref())?;
        let current_uid = fm.st_uid();
        match ctx.uidmap.get(&current_uid) {
            Some(new_uid) => {
                println!(
                    "{} -> Found: Changing uid from {current_uid} to {new_uid}",
                    p.as_ref().display()
                );
                if !ctx.noop {
                    match p.set_owner(*new_uid) {
                        Ok(_) => (),
                        Err(e) => {
                            eprintln!(
                                "{} -> Failed to set uid, error: {}",
                                p.as_ref().display(),
                                e
                            )
                        }
                    };
                }
            }
            None => (),
        };
        Ok(())
    }

    fn change_gid(ctx: &Ctx, p: &impl AsRef<Path>) -> Result<(), anyhow::Error> {
        println!("{} -> Scanning gids", p.as_ref().display());
        let fm = get_file_metadata(p.as_ref())?;
        let current_gid = fm.st_gid();
        match ctx.gidmap.get(&current_gid) {
            Some(new_gid) => {
                println!(
                    "{} -> Found: Changing gid from {current_gid} to {new_gid}",
                    p.as_ref().display()
                );
                if !ctx.noop {
                    match p.set_group(*new_gid) {
                        Ok(_) => (),
                        Err(e) => {
                            eprintln!(
                                "{} -> Failed to set gid, error: {}",
                                p.as_ref().display(),
                                e
                            )
                        }
                    };
                }
            }
            None => (),
        };
        Ok(())
    }

    fn process_path(ctx: &Ctx, p: &Path) -> Result<(), anyhow::Error> {
        println!("{} -> Started Processing", p.display());

        // Skip symlinks, they're nuthin but trouble
        if p.is_symlink() {
            println!("{} -> Skipping symlink", p.display());
            return Ok(());
        }

        // Run the logic to check and swap old uid with new uid
        change_uid(&ctx, &p)?;
        change_gid(&ctx, &p)?;

        // Modify the posix ACLs if flag was provided
        if ctx.modify_acls {
            acl::update_access_acl(&ctx, &p)?;
            if p.is_dir() {
                acl::update_default_acl(&ctx, &p)?;
            }
        }

        // If the item is a dir, do it all again!
        if p.is_dir() {
            run_dir(&ctx, &p)?;
        }

        Ok(())
    }

    fn run_dir(ctx: &Ctx, path: &Path) -> Result<(), anyhow::Error> {
        // do the stuff to the provided Path
        // process_path(&ctx, path)?;

        // then list all its children and do the stuff
        println!("{} -> Enumerating children", path.display());
        let file_listing = get_file_listing(&path)?;
        let files = parse_file_listing(file_listing);

        files.par_iter().for_each(move |f| {
            match process_path(&ctx, &f.path()) {
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
}

pub mod pairs {
    use anyhow::{bail, Result};
    use std::collections::HashMap;
    #[derive(Debug)]
    pub struct Idpair {
        old_id: u32,
        new_id: u32,
    }
    impl Idpair {
        pub fn from_string(idpair: &str) -> Result<Idpair, anyhow::Error> {
            let old_id = match idpair.split(':').nth(0) {
                Some(s) => match s.parse::<u32>() {
                    Ok(o) => o,
                    Err(_) => bail!("unable to parse id string '{s}' to int"),
                },
                None => bail!("invalid idpair. expected format (old:new) '890:211790'"),
            };
            let new_id = match idpair.split(':').nth(1) {
                Some(s) => match s.parse::<u32>() {
                    Ok(o) => o,
                    Err(_) => bail!("unable to parse id string '{s}' to int"),
                },
                None => bail!("invalid idpair. expected format (old:new) '890:211790'"),
            };
            // let new = idpair.split(":").nth(1)?.parse::<u32>()?;
            Ok(Idpair { old_id, new_id })
        }
    }

    pub fn get_map_from_pairs(pairs: Vec<String>) -> Result<HashMap<u32, u32>, anyhow::Error> {
        let mut idmap: HashMap<u32, u32> = HashMap::new();
        for pair in pairs {
            match Idpair::from_string(&pair) {
                Ok(u) => match idmap.insert(u.old_id, u.new_id) {
                    Some(_) => {
                        bail!("duplicate old id found in provided idpairs. check your input data.")
                    }
                    None => (),
                },
                Err(e) => bail!(e),
            }
        }
        Ok(idmap)
    }
}
