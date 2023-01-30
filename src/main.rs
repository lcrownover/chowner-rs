use anyhow::{bail, Result};
use clap::Parser;
use util::VerbosePrinter;

mod ctx;
mod files;
mod pairs;
mod acl;
mod util;

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

    /// verbose, print operations
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
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

    let ctx = ctx::Ctx {
        noop: args.noop,
        modify_acls: args.modify_acls,
        uidmap,
        gidmap,
        verbose_printer: VerbosePrinter::new(args.verbose),
    };

    // here we go
    files::start(&ctx, &args.path);

    Ok(())
}
