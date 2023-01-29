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
        println!("Scanning Access ACLs on path: {:?}", path.as_ref());
        let mut acl = match PosixACL::read_acl(path) {
            Ok(acl) => acl,
            Err(e) => bail!("Error reading ACL: {e}"),
        };
        for entry in acl.entries() {
            println!("Processing entry: {entry:?}");
            match entry.qual {
                Qualifier::User(uid) => {
                    let new_uid = ctx.uidmap.get(&uid);
                    match new_uid {
                        Some(new_uid) => {
                            println!("Uid {uid} found in ACL, replacing with uid {new_uid}");
                            if ctx.noop {
                                println!("noop, not making changes");
                                continue;
                            }
                            println!("Removing Access ACL for old uid: {uid}");
                            acl.remove(Qualifier::User(uid));
                            println!("Adding Access ACL for new uid: {new_uid}");
                            acl.set(Qualifier::User(*new_uid), entry.perm)
                        }
                        None => (),
                    }
                }
                Qualifier::Group(gid) => {
                    let new_gid = ctx.gidmap.get(&gid);
                    match new_gid {
                        Some(new_gid) => {
                            println!("Gid {gid} found in ACL, replacing with gid {new_gid}");
                            if ctx.noop {
                                println!("noop, not making changes");
                                continue;
                            }
                            println!("Removing Access ACL for old gid: {gid}");
                            acl.remove(Qualifier::Group(gid));
                            println!("Adding Access ACL for new gid: {new_gid}");
                            acl.set(Qualifier::Group(*new_gid), entry.perm)
                        }
                        None => (),
                    }
                }
                _ => (),
            }
        }
        println!("Writing changes to ACL");
        match acl.write_acl(path) {
            Ok(_) => println!("Successfully wrote changes to ACL"),
            Err(e) => bail!("Failed to write acl: {e}"),
        }
        Ok(())
    }

    pub fn update_default_acl(ctx: &Ctx, path: &impl AsRef<Path>) -> Result<(), anyhow::Error> {
        println!("Scanning Default ACLs on path: {:?}", path.as_ref());
        let mut acl = match PosixACL::read_default_acl(path) {
            Ok(acl) => acl,
            Err(e) => {
                bail!("Error reading default ACL. This should only be run against directories: {e}")
            }
        };
        for entry in acl.entries() {
            println!("Processing entry: {entry:?}");
            match entry.qual {
                Qualifier::User(uid) => {
                    let new_uid = ctx.uidmap.get(&uid);
                    match new_uid {
                        Some(new_uid) => {
                            println!("Uid {uid} found in ACL, replacing with uid {new_uid}");
                            if ctx.noop {
                                println!("noop, not making changes");
                                continue;
                            }
                            println!("Removing Default ACL for old uid: {uid}");
                            acl.remove(Qualifier::User(uid));
                            println!("Adding Default ACL for new uid: {new_uid}");
                            acl.set(Qualifier::User(*new_uid), entry.perm)
                        }
                        None => (),
                    }
                }
                Qualifier::Group(gid) => {
                    let new_gid = ctx.gidmap.get(&gid);
                    match new_gid {
                        Some(new_gid) => {
                            println!("Gid {gid} found in ACL, replacing with gid {new_gid}");
                            if ctx.noop {
                                println!("noop, not making changes");
                                continue;
                            }
                            println!("Removing Default ACL for old gid: {gid}");
                            acl.remove(Qualifier::Group(gid));
                            println!("Adding Default ACL for new gid: {new_gid}");
                            acl.set(Qualifier::Group(*new_gid), entry.perm)
                        }
                        None => (),
                    }
                }
                _ => (),
            }
        }
        println!("Writing changes to Default ACL");
        if !ctx.noop {
            match acl.write_acl(path) {
                Ok(_) => println!("Successfully wrote changes to Default ACL"),
                Err(e) => bail!("Failed to write acl: {e}"),
            }
        } else {
            println!("noop, not making changes");
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

    fn get_file_metadata(f: &DirEntry) -> Result<Metadata, anyhow::Error> {
        let fm = match f.metadata() {
            Ok(fm) => fm,
            Err(e) => {
                bail!("failed to parse file metadata: {e}");
            }
        };
        Ok(fm)
    }

    fn get_file_listing(path: &impl AsRef<Path>) -> Result<ReadDir, anyhow::Error> {
        let file_listing = match fs::read_dir(path) {
            Ok(f) => f,
            Err(e) => {
                bail!(
                    "failed to stat file: {}, error: {}",
                    path.as_ref().display(),
                    e
                );
            }
        };
        Ok(file_listing)
    }

    fn change_uid(ctx: &Ctx, f: &DirEntry) -> Result<(), anyhow::Error> {
        println!("Scanning uids");
        let fm = get_file_metadata(f)?;
        let current_uid = fm.st_uid();
        match ctx.uidmap.get(&current_uid) {
            Some(new_uid) => {
                println!(
                    "Found: Changing uid from {current_uid} to {new_uid} for file {}",
                    f.path().display()
                );
                if !ctx.noop {
                    match f.path().set_owner(*new_uid) {
                        Ok(_) => (),
                        Err(e) => eprintln!(
                            "Failed to set uid for file {}, error: {}",
                            f.path().display(),
                            e
                        ),
                    };
                }
            }
            None => (),
        };
        Ok(())
    }

    fn change_gid(ctx: &Ctx, f: &DirEntry) -> Result<(), anyhow::Error> {
        println!("Scanning gids");
        let fm = get_file_metadata(f)?;
        let current_gid = fm.st_gid();
        match ctx.gidmap.get(&current_gid) {
            Some(new_gid) => {
                println!(
                    "Found: Changing gid from {current_gid} to {new_gid} for file {}",
                    f.path().display()
                );
                if !ctx.noop {
                    match f.path().set_group(*new_gid) {
                        Ok(_) => (),
                        Err(e) => eprintln!(
                            "Failed to set gid for file {}, error: {}",
                            f.path().display(),
                            e
                        ),
                    };
                }
            }
            None => (),
        };
        Ok(())
    }

    fn process_dir_entry(ctx: &Ctx, f: &DirEntry) -> Result<(), anyhow::Error> {
        println!("Processing path: {}", f.path().display());
        let ft = match f.file_type() {
            Ok(ft) => ft,
            Err(e) => {
                bail!("failed to parse file type: {e}");
            }
        };

        // Skip symlinks, they're nuthin but trouble
        if ft.is_symlink() {
            println!("Skipping symlink: {}", f.path().display());
            return Ok(());
        }

        // Run the logic to check and swap old uid with new uid
        change_uid(&ctx, &f)?;
        change_gid(&ctx, &f)?;

        // Modify the posix ACLs if flag was provided
        if ctx.modify_acls {
            acl::update_access_acl(&ctx, &f.path())?;
            if ft.is_dir() {
                acl::update_default_acl(&ctx, &f.path())?;
            }
        }

        // If the item is a dir, do it all again!
        if ft.is_dir() {
            run_dir(&ctx, &f.path())?;
        }

        Ok(())
    }

    pub fn run_dir(ctx: &Ctx, path: &impl AsRef<Path>) -> Result<(), anyhow::Error> {
        // do the stuff to the provided Path

        // then list all its children and do the stuff
        println!(
            "Getting all files in directory: {}",
            path.as_ref().display()
        );
        let file_listing = get_file_listing(&path)?;
        let files = parse_file_listing(file_listing);

        files.par_iter().for_each(move |f| {
            match process_dir_entry(&ctx, &f) {
                Ok(_) => (),
                Err(e) => eprintln!("{e}"),
            };
        });

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
