
pub const DOMAIN: &'static str = "raiap.io";
pub const TYPE: &'static str = "anchor";

use serde::{Serialize, Deserialize};
use ed25519_dalek::{Keypair, PublicKey, Signature};

use sha2::{Sha256, Digest};
use base64::encode;

use crate::structs::Result;

pub fn al(sig: &Signature) -> String {
  let mut hasher = Sha256::new();
  hasher.input(sig.to_bytes().as_ref());
  let result = hasher.result();

  encode(&result)
}

pub fn asi(key: &PublicKey, sig: &Signature) -> String {
  let mut hasher = Sha256::new();
  hasher.input(key.as_bytes());
  hasher.input(sig.to_bytes().as_ref());
  let result = hasher.result();

  encode(&result)
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct Anchor {
  pub r: String,
  pub sn: usize,
  pub al: String
}

impl Anchor {
  pub fn new(keypair: &Keypair, udi: &str, r: &str, sn: usize) -> Self {
    let sig_data = Self::data(udi, r);
    let sig = keypair.sign(&sig_data);

    Self { r: r.into(), sn, al: al(&sig) }
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    bincode::serialize(self).unwrap()
  }

  pub fn from_bytes(bytes: &[u8]) -> Result<Anchor> {
    bincode::deserialize(bytes).map_err(|_|{ "Unable to deserialize anchor!".into() })
  }

  fn data(udi: &str, r: &str) -> Vec<u8> {
    let mut data = Vec::<u8>::new();

    // These unwrap() should never fail, or it's a serious code bug!
    data.extend(bincode::serialize(udi).unwrap());
    data.extend(bincode::serialize(r).unwrap());
    
    data
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::structs::identity::*;
  use rand::rngs::OsRng;
  use ed25519_dalek::Keypair;

  fn create() -> (Identity, Keypair) {
    let mut csprng = OsRng{};

    // create master group
    let m_keypair: Keypair = Keypair::generate(&mut csprng);
    let master = TLGroup::new(TLType::MASTER, &m_keypair.public);

    // create genesis card and identity
    let id_keypair: Keypair = Keypair::generate(&mut csprng);
    let genesis = Card::new(true, &id_keypair, b"No important info!", &vec![master.clone()]);
    let identity = Identity::new(genesis).unwrap();
    
    (identity, id_keypair)
  }

  #[test]
  fn create_anchor() {
    let mut csprng = OsRng{};
    let (mut identity, id_keypair) = create();
    
    // write anchor
    let profile_keypair: Keypair = Keypair::generate(&mut csprng);
    let anchor1 = Anchor::new(&profile_keypair, &identity.udi, "some-random", 0);
    let anchor_reg = Registry::new(&id_keypair, "raiap.io/test", "anchor", OType::SET, &anchor1.to_bytes(), identity.prev().unwrap(), 0);
    identity.save(anchor_reg).unwrap();

    // read anchor
    let anchor_reg_vec = identity.registry("raiap.io/test").unwrap();
    let anchor_reg = anchor_reg_vec.last().unwrap();
    let anchor2 = Anchor::from_bytes(&anchor_reg.info).unwrap();

    assert!(anchor1 == anchor2);
  }
}