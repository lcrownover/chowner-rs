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
        match acl.write_acl(path) {
            Ok(_) => println!("Successfully wrote changes to Default ACL"),
            Err(e) => bail!("Failed to write acl: {e}"),
        }
        Ok(())
    }
}

pub mod files {
    use crate::acl;
    use crate::Ctx;
    use file_owner::PathExt;
    use rayon::prelude::*;
    use std::fs;
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

    pub fn run_dir(ctx: &Ctx, path: &impl AsRef<Path>) {
        let file_listing = match fs::read_dir(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "failed to stat file: {}, error: {}",
                    path.as_ref().display(),
                    e
                );
                return;
            }
        };
        let files = parse_file_listing(file_listing);
        files.par_iter().for_each(move |f| {
            let ft = match f.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    eprintln!("failed to parse file type: {e}");
                    return;
                }
            };
            if ft.is_symlink() {
                return;
            }
            let fm = match f.metadata() {
                Ok(fm) => fm,
                Err(e) => {
                    eprintln!("failed to parse file metadata: {e}");
                    return;
                }
            };
            let current_uid = fm.st_uid();
            match ctx.uidmap.get(&current_uid) {
                Some(new_uid) => {
                    println!(
                        "PREVIEW: changing uid from {current_uid} to {new_uid} for file {}",
                        f.path().display()
                    );
                    if ctx.noop == false {
                        match f.path().set_owner(*new_uid) {
                            Ok(_) => (),
                            Err(e) => eprintln!(
                                "failed to set uid for file {}, error: {}",
                                f.path().display(),
                                e
                            ),
                        };
                        println!(
                            "CHANGED: current uid {:?}, new uid {}",
                            f.path().owner().unwrap().id(),
                            new_uid
                        );
                    }
                }
                None => (),
            };
            let current_gid = fm.st_gid();
            match ctx.gidmap.get(&current_gid) {
                Some(new_gid) => {
                    println!(
                        "PREVIEW: changing gid from {current_gid} to {new_gid} for file {}",
                        f.path().display()
                    );
                    if ctx.noop == false {
                        match f.path().set_group(*new_gid) {
                            Ok(_) => (),
                            Err(e) => eprintln!(
                                "failed to set gid for file {}, error: {}",
                                f.path().display(),
                                e
                            ),
                        };
                        println!(
                            "CHANGED: current gid {:?}, new gid {}",
                            f.path().group().unwrap().id(),
                            new_gid
                        );
                    }
                }
                None => (),
            };

            if ctx.modify_acls {
                match acl::update_access_acl(&ctx, &f.path()) {
                    Ok(_) => (),
                    Err(e) => eprintln!("{e}"),
                };
                if ft.is_dir() {
                    match acl::update_default_acl(&ctx, &f.path()) {
                        Ok(_) => (),
                        Err(e) => eprintln!("{e}"),
                    };
                }
            }

            if ft.is_dir() {
                run_dir(&ctx, &f.path())
            }
        });
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
