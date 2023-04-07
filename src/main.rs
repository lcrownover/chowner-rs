use anyhow::{bail, Result};
use clap::Parser;
use util::VerbosePrinter;

mod acl;
mod ctx;
mod files;
mod pairs;
mod run;
mod types;
mod util;

/// Blazingly fast filesystem modifier
#[derive(Parser)]
#[command(author, version, about, long_about = None, arg_required_else_help(true))]
struct Cli {
    /// Base paths for enumeration
    paths: Vec<String>,

    /// Number of threads to spawn
    #[arg(short, long, default_value_t = 0)]
    threads: usize,

    /// uid mapping (old:new)
    #[clap(short, long, value_parser, num_args = 0.., value_delimiter = ',')]
    uidpairs: Vec<String>,

    /// gid mapping (old:new)
    #[clap(short, long, value_parser, num_args = 0.., value_delimiter = ',')]
    gidpairs: Vec<String>,

    /// don't modify unix permissions
    #[arg(long, default_value_t = false)]
    skip_permissions: bool,

    /// don't modify unix acls
    #[arg(long, default_value_t = false)]
    skip_acls: bool,

    /// dry run, don't change anything
    #[arg(long)]
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

    if let Err(e) = pairs::check_pairs(&args.uidpairs, &args.gidpairs) {
        bail!(e)
    }

    let uidmap = match pairs::get_map_from_pairs(args.uidpairs) {
        Ok(m) => m,
        Err(e) => bail!(e),
    };

    let gidmap = match pairs::get_map_from_pairs(args.gidpairs) {
        Ok(m) => m,
        Err(e) => bail!(e),
    };

    let ctx = ctx::Ctx {
        noop: args.noop,
        skip_permissions: args.skip_permissions,
        skip_acls: args.skip_acls,
        uidmap,
        gidmap,
        verbose_printer: VerbosePrinter::new(args.verbose),
    };

    // here we go
    run::start(&ctx, &args.paths);

    Ok(())
}
