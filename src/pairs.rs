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
