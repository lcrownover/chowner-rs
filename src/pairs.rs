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
    pub fn from_string(idpair: &str) -> Result<Option<Idpair>, anyhow::Error> {
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
        if current_id == new_id {
            return Ok(None);
        }

        Ok(Some(Idpair { current_id, new_id }))
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
        let maybe_u = Idpair::from_string(&pair)?;
        match maybe_u {
            None => {
                println!("Skipping idpair with identical old and new id: {}", pair);
                continue;
            }
            Some(u) => {
                if let Some(_) = idmap.insert(u.current_id, u.new_id) {
                    // insert returns the value at that key if it already exists.
                    // we can discard the value and return an error since we dont want dupes.
                    bail!(
                        "Duplicate old '{}' id found in provided idpairs. Check your input data.",
                        u.current_id
                    )
                    // returns None if it doesnt exist, inserted successfully.
                }
            }
        };
    }
    Ok(idmap)
}

/// Returns an error if pairs don't pass checks
///
/// # Arguments
///
/// * `uidpairs` - UID pairs for user migration
/// * `gidpairs` - GID pairs for group migration
///
pub fn check_pairs(uidpairs: &Vec<String>, gidpairs: &Vec<String>) -> Result<(), anyhow::Error> {
    check_pair_duplicates(uidpairs, gidpairs)?;

    Ok(())
}

/// Returns an error if the flattened list of source/dest in all pairs contains duplicates
///
/// # Arguments
///
/// * `uidpairs` - UID pairs for user migration
/// * `gidpairs` - GID pairs for group migration
///
pub fn check_pair_duplicates(
    uidpairs: &Vec<String>,
    gidpairs: &Vec<String>,
) -> Result<(), anyhow::Error> {
    let allids = flatten_pairs(uidpairs, gidpairs);

    let dupes_len = allids.len();

    let mut dedups = allids.clone();
    dedups.sort();
    dedups.dedup();
    let dedup_len = dedups.len();

    if dupes_len != dedup_len {
        let mut seen = vec![];
        for id in allids {
            if seen.contains(&id) {
                println!("Duplicate ID found in source or destination pair: {}", id);
            }
            seen.push(id);
        }
        bail!("Duplicate ID found in source or destination pair.")
    }
    Ok(())
}

/// Returns a list of Strings of the flattened uidpairs and gidpairs into a single list of all IDs.
///
/// # Arguments
///
/// * `uidpairs` - UID pairs for user migration
/// * `gidpairs` - GID pairs for group migration
///
fn flatten_pairs(uidpairs: &Vec<String>, gidpairs: &Vec<String>) -> Vec<String> {
    // uidpairs: ["1:2", "3:4"], gidpairs: ["5:6", "7:8"]
    let allpairs = [uidpairs.clone(), gidpairs.clone()].concat();
    // allpairs: ["1:2", "3:4", "5:6", "7:8"]
    let mut allids: Vec<String> = vec![];
    for pair in allpairs {
        for i in pair.split(":") {
            allids.push(i.to_string());
        }
    }
    // allids: ["1", "2", "3", "4", "5", "6", "7", "8"]
    allids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_pair_duplicates_flattens_correctly() {
        let control = vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
            "4".to_string(),
            "5".to_string(),
            "6".to_string(),
            "7".to_string(),
            "8".to_string(),
        ];
        let uidpairs = vec!["1:2".to_string(), "3:4".to_string()];
        let gidpairs = vec!["5:6".to_string(), "7:8".to_string()];
        let flattened = flatten_pairs(&uidpairs, &gidpairs);
        assert_eq!(flattened, control)
    }

    #[test]
    fn check_pair_duplicates_finds_dupes_one_side() {
        let uidpairs = vec!["1:2".to_string(), "3:4".to_string()];
        let gidpairs = vec!["5:6".to_string(), "7:7".to_string()];
        assert!(check_pair_duplicates(&uidpairs, &gidpairs).is_err())
    }

    #[test]
    fn check_pair_duplicates_finds_dupes_both_sides() {
        let uidpairs = vec!["1:2".to_string(), "3:4".to_string()];
        let gidpairs = vec!["5:6".to_string(), "7:4".to_string()];
        assert!(check_pair_duplicates(&uidpairs, &gidpairs).is_err())
    }
}
