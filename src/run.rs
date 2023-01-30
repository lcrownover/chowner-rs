use crate::ctx::Ctx;
use crate::files;
use std::path::Path;
use rayon::prelude::*;

pub fn run_dir(ctx: &Ctx, path: &Path) {
    // handle errors in here because we want to gracefully continue
    // everything downstream should bail!() and bubble up here
    // if anything fails, we just error print, return a unit, and keep going

    // do the stuff to the provided Path with no recurse
    match files::process_path(&ctx, path, false) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    // then list all its children and do the stuff
    let files = match files::get_file_paths(path) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    files.par_iter().for_each(move |f| {
        match files::process_path(&ctx, &f.as_path(), true) {
            Ok(_) => (),
            Err(e) => eprintln!("{e}"),
        };
    });
}

pub fn start(ctx: &Ctx, path: &impl AsRef<Path>) {
    run_dir(&ctx, path.as_ref());
}
