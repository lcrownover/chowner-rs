use crate::ctx::Ctx;
use crate::files;
use rayon::prelude::*;
use std::path::Path;

/// Main recursive function that operates on directories.
///
/// # Arguments
///
/// * `ctx` - Context object used throughout the application
///
/// * `path` - Path to the filesystem object
///
pub fn run_recurse(ctx: &Ctx, path: &Path) {
    // handle errors in here because we want to gracefully continue
    // everything downstream should bail!() and bubble up here
    // if anything fails, we just error print, return a unit, and keep going

    // do the stuff to the provided Path with no recurse
    files::process_path(&ctx, path);

    // We only want to recurse through non-symlink dirs
    if path.is_symlink() || !path.is_dir() {
        return;
    }

    // then list all its children and do the stuff
    let files = match files::get_children_paths(path) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    files.par_iter().for_each(move |f| {
        run_recurse(&ctx, &f.as_path());
    });
}

/// Primary entrypoint for starting the application after parsing command-line args
/// and building a context object.
///
/// # Arguments
///
/// * `ctx` - Context object used throughout the application
///
/// * `path` - Path to the filesystem object
///
pub fn start(ctx: &Ctx, path: &impl AsRef<Path>) {
    run_recurse(&ctx, path.as_ref());
}
