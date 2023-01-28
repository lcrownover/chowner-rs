use anyhow::{bail, Result};
use clap::Parser;
use file_owner::PathExt;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs::{self, DirEntry, ReadDir};
use std::io;
use std::os::macos::fs::MetadataExt;
use std::path::Path;
use std::process::exit;

#[derive(Debug)]
struct Idpair {
    old_id: u32,
    new_id: u32,
}
impl Idpair {
    fn from_string(idpair: &str) -> Result<Idpair, anyhow::Error> {
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

fn get_map_from_pairs(pairs: Vec<String>) -> Result<HashMap<u32, u32>, anyhow::Error> {
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

#[derive(Debug)]
struct Ctx {
    noop: bool,
    modify_acls: bool,
    uidmap: HashMap<u32, u32>,
    gidmap: HashMap<u32, u32>,
}

/// Blazingly fast filesystem modifier
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Base path for enumeration
    path: String,

    /// Number of threads to spawn
    #[arg(short, long, default_value_t = 0)]
    threads: usize,

    /// uid mapping (old:new)
    #[arg(short, long)]
    uidpair: Vec<String>,

    /// gid mapping (old:new)
    #[arg(short, long)]
    gidpair: Vec<String>,

    /// modify unix acls
    #[arg(short, long, default_value_t = false)]
    modify_acls: bool,

    /// dry run, don't change anything
    #[arg(short, long)]
    noop: bool,
}

fn parse_file_listing(files: ReadDir) -> Vec<DirEntry> {
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

fn run_dir(ctx: &Ctx, path: &impl AsRef<Path>) {
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
                        Err(e) => eprintln!("failed to set uid for file {}, error: {}", f.path().display(), e)
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
                        Err(e) => eprintln!("failed to set gid for file {}, error: {}", f.path().display(), e)
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

        // need to get acls too but i cant do that on mac
        if ctx.modify_acls {
            println!("modifying acls")
        }

        if ft.is_dir() {
            run_dir(&ctx, &f.path())
        }
    });
}

fn main() -> Result<()> {
    let args = Cli::parse();
    if args.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()?;
    }
    let uidmap = match get_map_from_pairs(args.uidpair) {
        Ok(m) => m,
        Err(e) => bail!(e),
    };
    let gidmap = match get_map_from_pairs(args.gidpair) {
        Ok(m) => m,
        Err(e) => bail!(e),
    };

    let ctx = Ctx {
        noop: args.noop,
        modify_acls: args.modify_acls,
        uidmap,
        gidmap,
    };

    // just verify before fucking things up
    println!("{ctx:?}");
    println!(
        "Running recursively against path '{}', continue? [y/n]",
        args.path
    );
    let mut ans = String::new();
    io::stdin().read_line(&mut ans).unwrap();
    if ans.trim() != "y".to_string() {
        println!("exiting");
        exit(0)
    }

    // here we go
    run_dir(&ctx, &args.path);

    Ok(())
}
