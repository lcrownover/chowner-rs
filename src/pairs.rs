use anyhow::{bail, Result};
use std::collections::HashMap;

/// Contains a relationship of a current uid/gid to a new uid/gid
#[derive(Debug)]
pub struct Idpair {
    /// This id will be overwritten by `new_id`
    current_id: u32,
    /// The new id for the object
    new_id: u32,
}

impl Idpair {
    /// Parse an Idpair from a string
    ///
    /// # Example
    ///
    /// ```
    /// let pair = Idpair::from_string("57:211790")
    /// // Pair {
    /// //     current_id: 57,
    /// //     new_id: 211790,
    /// // }
    /// ```
    ///
    pub fn from_string(idpair: &str) -> Result<Idpair, anyhow::Error> {
        let current_id = match idpair.split(':').nth(0) {
            Some(s) => match s.parse::<u32>() {
                Ok(o) => o,
                Err(_) => bail!("Unable to parse id string '{s}' to int"),
            },
            None => bail!("Invalid idpair. Expected format (old:new) '890:211790'"),
        };
        let new_id = match idpair.split(':').nth(1) {
            Some(s) => match s.parse::<u32>() {
                Ok(o) => o,
                Err(_) => bail!("Unable to parse id string '{s}' to int"),
            },
            None => bail!("Invalid idpair. expected format (old:new) '890:211790'"),
        };
        // let new = idpair.split(":").nth(1)?.parse::<u32>()?;
        Ok(Idpair { current_id, new_id })
    }
}

/// Returns a `HashMap` where each entry relates to an Idpair,
/// and each entry's key is the current_id and the value is the new_id
///
/// # Arguments
///
/// * `pairs` - List of strings to be converted to pairs, then stored in the `HashMap`
///
pub fn get_map_from_pairs(pairs: Vec<String>) -> Result<HashMap<u32, u32>, anyhow::Error> {
    let mut idmap: HashMap<u32, u32> = HashMap::new();
    for pair in pairs {
        match Idpair::from_string(&pair) {
            Ok(u) => match idmap.insert(u.current_id, u.new_id) {
                Some(_) => {
                    bail!("Duplicate old id found in provided idpairs. Check your input data.")
                }
                None => (),
            },
            Err(e) => bail!(e),
        }
    }
    Ok(idmap)
}
