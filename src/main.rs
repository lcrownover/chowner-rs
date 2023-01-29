use anyhow::{bail, Result};
use clap::Parser;
use std::io;
use std::process::exit;

use chowner_rs::files;
use chowner_rs::acl;
use chowner_rs::pairs;
use chowner_rs::Ctx;

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

fn main() -> Result<()> {
    let args = Cli::parse();
    if args.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()?;
    }

    let uidmap = match pairs::get_map_from_pairs(args.uidpair) {
        Ok(m) => m,
        Err(e) => bail!(e),
    };

    let gidmap = match pairs::get_map_from_pairs(args.gidpair) {
        Ok(m) => m,
        Err(e) => bail!(e),
    };

    let ctx = Ctx {
        noop: args.noop,
        modify_acls: args.modify_acls,
        uidmap,
        gidmap,
    };

    if args.modify_acls {
        acl::update_acl(&ctx, &args.path)
    }

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
    files::run_dir(&ctx, &args.path);

    Ok(())
}
