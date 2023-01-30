#[derive(Debug)]
pub struct VerbosePrinter {
    verbosity_level: u8,
}

impl VerbosePrinter {
    pub fn new(verbosity_level: u8) -> Self {
        return Self { verbosity_level }
    }

    pub fn print1(&self, message: String) {
        if self.verbosity_level >= 1 {
            println!("{}", message);
        }
    }

    pub fn print2(&self, message: String) {
        if self.verbosity_level >= 2 {
            println!("{}", message);
        }
    }

    pub fn print3(&self, message: String) {
        if self.verbosity_level >= 3 {
            println!("{}", message);
        }
    }
}
